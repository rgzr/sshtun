# sshtun

[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](https://godoc.org/github.com/rgzr/sshtun)

sshtun is a Go package that provides a SSH tunnel with port forwarding supporting:

* TCP and unix socket connections
* Password authentication
* Un/encrypted key file authentication
* `ssh-agent` based authentication
* Both local and remote port forwarding

By default it reads the default linux ssh private key locations and fallbacks to using `ssh-agent`, but a specific authentication method can be set.

The default locations are `~/.ssh/id_rsa`, `~/.ssh/id_dsa`, `~/.ssh/id_ecdsa`, `~/.ssh/id_ecdsa_sk`, `~/.ssh/id_ed25519` and `~/.ssh/id_ed25519_sk`.


## Installation

`go get github.com/rgzr/sshtun`

## Example

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/rgzr/sshtun"
)

func main() {
	// We want to connect to port 8080 on our machine to acces port 80 on my.super.host.com
	sshTun := sshtun.New(8080, "my.super.host.com", 80)

	// We print each tunneled state to see the connections status
	sshTun.SetTunneledConnState(func(tun *sshtun.SSHTun, state *sshtun.TunneledConnState) {
		log.Printf("%+v", state)
	})

	// We set a callback to know when the tunnel is ready
	sshTun.SetConnState(func(tun *sshtun.SSHTun, state sshtun.ConnState) {
		switch state {
		case sshtun.StateStarting:
			log.Printf("STATE is Starting")
		case sshtun.StateStarted:
			log.Printf("STATE is Started")
		case sshtun.StateStopped:
			log.Printf("STATE is Stopped")
		}
	})

	// We start the tunnel (and restart it every time it is stopped)
	go func() {
		for {
			if err := sshTun.Start(context.Background()); err != nil {
				log.Printf("SSH tunnel error: %v", err)
				time.Sleep(time.Second) // don't flood if there's a start error :)
			}
		}
	}()

	// We stop the tunnel every 20 seconds (just to see what happens)
	for {
		time.Sleep(time.Second * time.Duration(20))
		log.Println("Lets stop the SSH tunnel...")
		sshTun.Stop()
	}
}
```
