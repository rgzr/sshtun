package main

import (
	"log"
	"time"

	"github.com/rgzr/sshtun"
)

func main() {
	// We want to connect to port 8080 on our machine to access port 80 on my.super.host.com
	sshTun := sshtun.New(8080, "my.super.host.com", 80)

	// We enable debug messages to see what happens
	sshTun.SetDebug(true)

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

	// We set a callback to know the state of the forwarded connections
	sshTun.SetForwardedConnState(func(tun *sshtun.SSHTun, state sshtun.ForwardedConnState, forwardCounter int) {
		switch state {
		case sshtun.StateAccepted:
			log.Printf("Forward %d STATE is Accepted", forwardCounter)
		case sshtun.StateOpen:
			log.Printf("Forward %d STATE is Open", forwardCounter)
		case sshtun.StateClosed:
			log.Printf("Forward %d STATE is Closed", forwardCounter)
		case sshtun.StateFailed:
			log.Printf("Forward %d STATE is Failed", forwardCounter)
		case sshtun.StateRemoteDropped:
			log.Printf("Forward %d STATE is Dropped", forwardCounter)
		}
	})

	// We start the tunnel (and restart it every time it is stopped)
	go func() {
		for {
			if err := sshTun.Start(); err != nil {
				log.Printf("SSH tunnel stopped: %s", err.Error())
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
