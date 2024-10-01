package sshtun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avast/retry-go"
	"github.com/gliderlabs/ssh"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

type testServers struct {
	localPort  int
	sshPort    int
	remotePort int

	sshServer      *ssh.Server
	pingPongServer *net.TCPListener
	sshTun         *SSHTun

	pingPongConnections atomic.Int32
}

func newTestServers(localPort, sshPort, remotePort int) *testServers {
	sshServer := &ssh.Server{
		LocalPortForwardingCallback: ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool {
			return true
		}),
		Addr: fmt.Sprintf(":%d", sshPort),
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip": ssh.DirectTCPIPHandler,
		},
	}

	sshTun := New(localPort, "localhost", remotePort, Local)
	sshTun.SetPort(sshPort)

	return &testServers{
		localPort:  localPort,
		sshPort:    sshPort,
		remotePort: remotePort,
		sshServer:  sshServer,
		sshTun:     sshTun,
	}
}

func (s *testServers) start(ctx context.Context) error {
	errGroup, groupCtx := errgroup.WithContext(ctx)

	errGroup.Go(func() error {
		return s.serveSSH(groupCtx)
	})

	errGroup.Go(func() error {
		return s.servePingPong(groupCtx)
	})

	errGroup.Go(func() error {
		return s.sshTun.Start(groupCtx)
	})

	return errGroup.Wait()
}

func (s *testServers) serveSSH(ctx context.Context) error {
	errCh := make(chan error)

	go func() {
		err := s.sshServer.ListenAndServe()
		if err == ssh.ErrServerClosed {
			err = nil
		}

		errCh <- err
	}()

	<-ctx.Done()

	s.sshServer.Close()

	return <-errCh
}

func (s *testServers) servePingPong(ctx context.Context) error {
	errCh := make(chan error)

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{
		Port: s.remotePort,
	})
	if err != nil {
		return err
	}

	s.pingPongServer = listener

	go func() {
		errCh <- s.handlePingPongConnections(ctx)
	}()

	<-ctx.Done()

	s.pingPongServer.Close()

	return <-errCh
}

func (s *testServers) handlePingPongConnections(ctx context.Context) error {
	for i := 0; ; i++ {
		conn, err := s.pingPongServer.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return err
		}

		go func(connID int) {
			handleErr := s.handlePingPongConnection(conn)
			if handleErr != nil {
				log.Printf("conn %d: %v", connID, handleErr)
			}
		}(i)
	}
}

func (s *testServers) handlePingPongConnection(conn *net.TCPConn) error {
	s.pingPongConnections.Add(1)
	defer s.pingPongConnections.Add(-1)

	for {
		recv := make([]byte, 4)
		readBytes, err := io.ReadAtLeast(conn, recv, 4)
		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}

		if readBytes != 4 {
			return errors.New("not read 4 bytes")
		}

		if string(recv) != "ping" {
			return errors.New("not received ping")
		}

		writeBytes, err := io.WriteString(conn, "pong")
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			return err
		}

		if writeBytes != 4 {
			return errors.New("not write 4 bytes")
		}
	}
}

type pingPongClient struct {
	servers *testServers
	conn    *net.TCPConn
	pings   int
}

func (s *testServers) connectPingPong() (*pingPongClient, error) {
	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		Port: s.localPort,
	})

	if err != nil {
		return nil, err
	}

	return &pingPongClient{
		servers: s,
		conn:    conn,
	}, nil
}

func (c *pingPongClient) ping() error {
	sentBytes, err := io.WriteString(c.conn, "ping")
	if err != nil {
		return err
	}

	if sentBytes != 4 {
		return errors.New("not sent 4 bytes")
	}

	recv := make([]byte, 4)
	recvBytes, err := io.ReadAtLeast(c.conn, recv, 4)
	if err != nil {
		return err
	}

	if recvBytes != 4 {
		return errors.New("not received 4 bytes")
	}

	if string(recv) != "pong" {
		return errors.New("not received pong")
	}

	c.pings++

	return nil
}

func (c *pingPongClient) close() error {
	return c.conn.Close()
}

func runTestServers(t *testing.T) (*testServers, chan error, context.CancelFunc) {
	t.Helper()

	sshPort, err := freeport.GetFreePort()
	require.NoError(t, err)

	localPort, err := freeport.GetFreePort()
	require.NoError(t, err)

	remotePort, err := freeport.GetFreePort()
	require.NoError(t, err)

	testServers := newTestServers(localPort, sshPort, remotePort)

	testServers.sshTun.SetConnState(func(tun *SSHTun, connState ConnState) {
		switch connState {
		case StateStarting:
			t.Log("ConnState: starting")
		case StateStarted:
			t.Log("ConnState: started")
		case StateStopped:
			t.Log("ConnState: stopped")
		default:
			t.Log("ConnState: unexpected")
		}
	})

	testServers.sshTun.SetTunneledConnState(func(tun *SSHTun, tunneledConnState *TunneledConnState) {
		t.Logf("TunneledConnState: %+v\n", tunneledConnState)
	})

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error)
	go func() {
		errServers := testServers.start(ctx)
		if errServers != nil {
			log.Println(errServers.Error())
		}

		errCh <- errServers
	}()

	return testServers, errCh, cancel
}

func pingPongConnect(t *testing.T, testServers *testServers) *pingPongClient {
	t.Helper()

	var client *pingPongClient
	var err error

	err = retry.Do(func() error {
		client, err = testServers.connectPingPong()
		return err
	}, retry.Attempts(5), retry.Delay(500*time.Millisecond))

	require.NoError(t, err)

	return client
}

func TestOneConnection(t *testing.T) {
	testServers, errCh, cancel := runTestServers(t)

	client := pingPongConnect(t, testServers)

	err := client.ping()
	require.NoError(t, err)

	require.Equal(t, 1, client.pings)

	err = client.close()
	require.NoError(t, err)

	cancel()
	err = <-errCh

	require.NoError(t, err)
}

func TestMultipleConnections(t *testing.T) {
	testServers, errCh, cancel := runTestServers(t)

	client1 := pingPongConnect(t, testServers)

	client2 := pingPongConnect(t, testServers)

	err := client1.ping()
	require.NoError(t, err)

	err = client2.ping()
	require.NoError(t, err)

	err = client1.ping()
	require.NoError(t, err)

	require.Equal(t, 2, client1.pings)
	require.Equal(t, 1, client2.pings)

	err = client1.close()
	require.NoError(t, err)

	err = client2.ping()
	require.NoError(t, err)

	require.Equal(t, 2, client2.pings)

	err = client2.close()
	require.NoError(t, err)

	cancel()
	err = <-errCh

	require.NoError(t, err)
}

func checkTunConnections(t *testing.T, testServers *testServers, connections int) error {
	t.Helper()

	testServers.sshTun.mutex.Lock()
	defer testServers.sshTun.mutex.Unlock()

	if connections != testServers.sshTun.active {
		return fmt.Errorf("there are %d active connections instead of %d expected", testServers.sshTun.active, connections)
	}

	if connections == 0 && testServers.sshTun.sshClient != nil {
		return fmt.Errorf("ssh client should be nil")
	}

	if connections != 0 && testServers.sshTun.sshClient == nil {
		return fmt.Errorf("ssh client should not be nil")
	}

	return nil
}

func TestReconnectTunnel(t *testing.T) {
	testServers, errCh, cancel := runTestServers(t)

	require.NoError(t, checkTunConnections(t, testServers, 0))

	client := pingPongConnect(t, testServers)

	err := client.ping()
	require.NoError(t, err)

	require.NoError(t, checkTunConnections(t, testServers, 1))

	err = client.close()
	require.NoError(t, err)

	err = retry.Do(func() error {
		return checkTunConnections(t, testServers, 0)
	}, retry.Attempts(5), retry.Delay(500*time.Millisecond))

	require.NoError(t, err)

	client = pingPongConnect(t, testServers)

	err = client.ping()
	require.NoError(t, err)

	require.NoError(t, checkTunConnections(t, testServers, 1))

	err = client.close()
	require.NoError(t, err)

	cancel()
	err = <-errCh

	require.NoError(t, err)
}
