// Package sshtun provides a SSH tunnel with port forwarding. By default it reads the default linux ssh private key location ($HOME/.ssh/id_rsa).
package sshtun

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"io/ioutil"
	"os/user"

	"golang.org/x/crypto/ssh"
)

type Endpoint struct {
	Host       string
	Port       int
	UnixSocket string
}

func (e *Endpoint) connectionString() string {
	if e.UnixSocket != "" {
		return e.UnixSocket
	}
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

func (e *Endpoint) connectionType() string {
	if e.UnixSocket != "" {
		return "unix"
	}
	return "tcp"
}

// SSHTun represents a SSH tunnel
type SSHTun struct {
	*sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	errCh     chan error
	user      string
	password  string
	keyFile   string
	useKey    bool
	server    Endpoint
	local     Endpoint
	remote    Endpoint
	started   bool
	timeout   time.Duration
	debug     bool
	connState func(*SSHTun, ConnState)
}

// ConnState represents the state of the SSH tunnel. It's returned to an optional function provided to SetConnState.
type ConnState int

const (
	// StateStopped represents a stopped tunnel. A call to Start will make the state to transition to StateStarting.
	StateStopped ConnState = iota

	// StateStarting represents a tunnel initializing and preparing to listen for connections.
	// A successful initialization will make the state to transition to StateStarted, otherwise it will transition to StateStopped.
	StateStarting

	// StateStarted represents a tunnel ready to accept connections.
	// A call to stop or an error will make the state to transition to StateStopped.
	StateStarted
)

// New creates a new SSH tunnel to the specified server redirecting a port on local localhost to a port on remote localhost.
// By default the SSH connection is made to port 22 as root and using the default linux private key location ($HOME/.ssh/id_rsa).
// Calling SetPassword will change the authentication to password based and with SetKeyFile another key can be specified.
// The SSH user and port can be changed with SetUser and SetPort.
// The local and remote hosts can be changed to something different than localhost with SetLocalHost and SetRemoteHost.
// The states of the tunnel can be received throgh a callback function with SetConnState.
func New(localPort int, server string, remotePort int) *SSHTun {
	return &SSHTun{
		Mutex: &sync.Mutex{},
		server: Endpoint{
			Host: server,
			Port: 22,
		},
		user:     "root",
		password: "",
		keyFile:  "",
		useKey:   true,
		local: Endpoint{
			Host: "localhost",
			Port: localPort,
		},
		remote: Endpoint{
			Host: "localhost",
			Port: remotePort,
		},
		started: false,
		timeout: time.Second * 15,
		debug:   false,
	}
}

func NewUnix(localUnixSocket string, server string, remoteUnixSocket string) *SSHTun {
	return &SSHTun{
		Mutex: &sync.Mutex{},
		server: Endpoint{
			Host: server,
			Port: 22,
		},
		user:     "root",
		password: "",
		keyFile:  "",
		useKey:   true,
		local: Endpoint{
			UnixSocket: localUnixSocket,
		},
		remote: Endpoint{
			UnixSocket: remoteUnixSocket,
		},
		started: false,
		timeout: time.Second * 15,
		debug:   false,
	}
}

// SetPort changes the port where the SSH connection will be made.
func (tun *SSHTun) SetPort(port int) {
	tun.server.Port = port
}

// SetUser changes the user used to make the SSH connection.
func (tun *SSHTun) SetUser(user string) {
	tun.user = user
}

// SetKeyFile changes the authentication to key-based and uses the specified file.
// Leaving it empty defaults to the default linux private key location ($HOME/.ssh/id_rsa).
func (tun *SSHTun) SetKeyFile(file string) {
	tun.keyFile = file
	tun.useKey = true
}

// SetPassword changes the authentication to password-based and uses the specified password.
func (tun *SSHTun) SetPassword(password string) {
	tun.password = password
	tun.useKey = false
}

// SetLocalHost sets the local host to redirect (defaults to localhost)
func (tun *SSHTun) SetLocalHost(host string) {
	tun.local.Host = host
}

// SetRemoteHost sets the remote host to redirect (defaults to localhost)
func (tun *SSHTun) SetRemoteHost(host string) {
	tun.remote.Host = host
}

// SetTimeout sets the connection timeouts (defaults to 15 seconds).
func (tun *SSHTun) SetTimeout(timeout time.Duration) {
	tun.timeout = timeout
}

// SetDebug enables or disables log messages (disabled by default).
func (tun *SSHTun) SetDebug(debug bool) {
	tun.debug = debug
}

// SetConnState specifies an optional callback function that is called when a SSH tunnel changes state.
// See the ConnState type and associated constants for details.
func (tun *SSHTun) SetConnState(connStateFun func(*SSHTun, ConnState)) {
	tun.connState = connStateFun
}

// Start starts the SSH tunnel. After this call, all Set* methods will have no effect until Close is called.
func (tun *SSHTun) Start() error {
	tun.Lock()

	if tun.connState != nil {
		tun.connState(tun, StateStarting)
	}

	// SSH config
	config := &ssh.ClientConfig{
		User: tun.user,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: tun.timeout,
	}
	if tun.useKey {
		if tun.keyFile == "" {
			usr, _ := user.Current()
			if usr != nil {
				tun.keyFile = usr.HomeDir + "/.ssh/id_rsa"
			} else {
				tun.keyFile = "/root/.ssh/id_rsa"
			}
		}
		buf, err := ioutil.ReadFile(tun.keyFile)
		if err != nil {
			return tun.errNotStarted(fmt.Errorf("Error reading SSH key file %s: %s", tun.keyFile, err.Error()))
		}
		key, err := ssh.ParsePrivateKey(buf)
		if err != nil {
			return tun.errNotStarted(fmt.Errorf("Error parsing key file %s: %s", tun.keyFile, err.Error()))
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(key)}
	} else {
		config.Auth = []ssh.AuthMethod{ssh.Password(tun.password)}
	}

	local := tun.local.connectionString()
	// Local listener
	localList, err := net.Listen(tun.local.connectionType(), local)
	if err != nil {
		return tun.errNotStarted(fmt.Errorf("Local listen on %s failed: %s", local, err.Error()))
	}

	// Context and error channel
	tun.ctx, tun.cancel = context.WithCancel(context.Background())
	tun.errCh = make(chan error)

	// Accept connections
	go func() {
		for {
			localConn, err := localList.Accept()
			if err != nil {
				tun.errStarted(fmt.Errorf("Local accept on %s failed: %s", local, err.Error()))
				break
			}
			if tun.debug {
				log.Printf("Accepted connection from %s", localConn.RemoteAddr().String())
			}

			// Launch the forward
			go tun.forward(localConn, config)
		}
	}()

	// Wait until someone cancels the context and stop accepting connections
	go func() {
		select {
		case <-tun.ctx.Done():
			localList.Close()
		}
	}()

	// Now others can call Stop or fail
	if tun.debug {
		log.Printf("Listening on %s", local)
	}
	tun.started = true
	if tun.connState != nil {
		tun.connState(tun, StateStarted)
	}
	tun.Unlock()

	// Wait to exit
	select {
	case errFromCh := <-tun.errCh:
		return errFromCh
	}
}

func (tun *SSHTun) errNotStarted(err error) error {
	tun.started = false
	if tun.connState != nil {
		tun.connState(tun, StateStopped)
	}
	tun.Unlock()
	return err
}

func (tun *SSHTun) errStarted(err error) {
	tun.Lock()
	if tun.started {
		tun.cancel()
		if tun.connState != nil {
			tun.connState(tun, StateStopped)
		}
		tun.started = false
		tun.errCh <- err
	}
	tun.Unlock()
}

func (tun *SSHTun) forward(localConn net.Conn, config *ssh.ClientConfig) {
	defer localConn.Close()

	local := tun.local.connectionString()
	server := tun.server.connectionString()
	remote := tun.remote.connectionString()

	sshConn, err := ssh.Dial(tun.server.connectionType(), server, config)
	if err != nil {
		tun.errStarted(fmt.Errorf("SSH connection to %s failed: %s", server, err.Error()))
		return
	}
	defer sshConn.Close()
	if tun.debug {
		log.Printf("SSH connection to %s done", server)
	}

	remoteConn, err := sshConn.Dial(tun.remote.connectionType(), remote)
	if err != nil {
		if tun.debug {
			log.Printf("Remote dial to %s failed: %s", remote, err.Error())
		}
		return
	}
	defer remoteConn.Close()
	if tun.debug {
		log.Printf("Remote connection to %s done", remote)
	}

	connStr := fmt.Sprintf("%s -(tcp)> %s -(ssh)> %s -(tcp)> %s", localConn.RemoteAddr().String(), local, server, remote)
	if tun.debug {
		log.Printf("SSH tunnel OPEN: %s", connStr)
	}

	myCtx, myCancel := context.WithCancel(tun.ctx)

	go func() {
		_, err = io.Copy(remoteConn, localConn)
		if err != nil {
			//log.Printf("Error on io.Copy remote->local on connection %s: %s", connStr, err.Error())
			myCancel()
			return
		}
	}()

	go func() {
		_, err = io.Copy(localConn, remoteConn)
		if err != nil {
			//log.Printf("Error on io.Copy local->remote on connection %s: %s", connStr, err.Error())
			myCancel()
			return
		}
	}()

	select {
	case <-myCtx.Done():
		myCancel()
		if tun.debug {
			log.Printf("SSH tunnel CLOSE: %s", connStr)
		}
	}
}

// Stop closes the SSH tunnel and its connections.
// After this call all Set* methods will have effect and Start can be called again.
func (tun *SSHTun) Stop() {
	tun.errStarted(nil)
}
