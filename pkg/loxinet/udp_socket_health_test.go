package loxinet

import (
	"net"
	"testing"
	"time"
)

func TestUDPSocketHealth(t *testing.T) {
	open, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()

	closed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	closedAddress := closed.LocalAddr().String()
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}

	timeout := 150 * time.Millisecond
	for range 5 {
		openResult := make(chan bool, 1)
		go func() { openResult <- probeUDPSocket(open.LocalAddr().String(), timeout) }()
		if probeUDPSocket(closedAddress, timeout) {
			t.Fatal("closed UDP socket was marked healthy")
		}
		if !<-openResult {
			t.Fatal("open silent UDP socket was marked unhealthy")
		}
	}
}
