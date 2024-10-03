package sshtun

import (
	"context"
	"fmt"
	"io"
	"net"

	"golang.org/x/sync/errgroup"
)

// TunneledConnState represents the state of the final connections made through the tunnel.
type TunneledConnState struct {
	// From is the address initating the connection.
	From string
	// Info holds a message with info on the state of the connection (useful for debug purposes).
	Info string
	// Error holds an error on the connection or nil if the connection is successful.
	Error error
	// Ready indicates if the connection is established.
	Ready bool
	// Closed indicates if the connection is closed.
	Closed bool
}

func (s *TunneledConnState) String() string {
	out := fmt.Sprintf("[%s] ", s.From)
	if s.Info != "" {
		out += s.Info
	}
	if s.Error != nil {
		out += fmt.Sprintf("Error: %v", s.Error)
	}
	return out
}

func (tun *SSHTun) forward(fromConn net.Conn) {
	from := fromConn.RemoteAddr().String()

	tun.tunneledState(&TunneledConnState{
		From: from,
		Info: fmt.Sprintf("accepted %s connection", tun.fromEndpoint().Type()),
	})

	var toConn net.Conn
	var err error

	dialFunc := tun.sshClient.Dial
	if tun.forwardType == Remote {
		dialFunc = net.Dial
	}

	toConn, err = dialFunc(tun.toEndpoint().Type(), tun.toEndpoint().String())
	if err != nil {
		tun.tunneledState(&TunneledConnState{
			From: from,
			Error: fmt.Errorf("%s dial %s to %s failed: %w", tun.forwardToName(),
				tun.toEndpoint().Type(), tun.toEndpoint().String(), err),
		})

		fromConn.Close()
		return
	}

	connStr := fmt.Sprintf("%s -(%s)> %s <(ssh)> %s -(%s)> %s", from, tun.fromEndpoint().Type(),
		tun.fromEndpoint().String(), tun.server.String(), tun.toEndpoint().Type(), tun.toEndpoint().String())

	tun.tunneledState(&TunneledConnState{
		From:   from,
		Info:   fmt.Sprintf("connection established: %s", connStr),
		Ready:  true,
		Closed: false,
	})

	connCtx, connCancel := context.WithCancel(tun.ctx)
	errGroup := &errgroup.Group{}

	errGroup.Go(func() error {
		defer connCancel()
		_, err = io.Copy(toConn, fromConn)
		if err != nil {
			return fmt.Errorf("failed copying bytes from %s to %s: %w", tun.forwardToName(), tun.forwardFromName(), err)
		}
		return nil
	})

	errGroup.Go(func() error {
		defer connCancel()
		_, err = io.Copy(fromConn, toConn)
		if err != nil {
			return fmt.Errorf("failed copying bytes from %s to %s: %w", tun.forwardFromName(), tun.forwardToName(), err)
		}
		return nil
	})

	<-connCtx.Done()

	fromConn.Close()
	toConn.Close()

	err = errGroup.Wait()

	select {
	case <-tun.ctx.Done():
	default:
		if err != nil {
			tun.tunneledState(&TunneledConnState{
				From:   from,
				Error:  err,
				Closed: true,
			})
		}
	}

	tun.tunneledState(&TunneledConnState{
		From:   from,
		Info:   fmt.Sprintf("connection closed: %s", connStr),
		Closed: true,
	})
}

func (tun *SSHTun) tunneledState(state *TunneledConnState) {
	if tun.tunneledConnState != nil {
		tun.tunneledConnState(tun, state)
	}
}
