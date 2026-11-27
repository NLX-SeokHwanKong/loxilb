package loxinet

import (
	"bufio"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestQuicReadinessSocket(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply string
		want  bool
	}{
		{name: "ready", reply: "1", want: true},
		{name: "not ready", reply: "0"},
		{name: "deadline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "q.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			received := make(chan string, 1)
			probeDone := make(chan struct{})
			defer close(probeDone)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				addr, _ := bufio.NewReader(conn).ReadString('\n')
				received <- addr
				if tc.reply == "" {
					<-probeDone
				} else {
					_, _ = conn.Write([]byte(tc.reply))
				}
			}()
			if got := requestQuicReadiness(socket, "192.0.2.7:16968", 100*time.Millisecond); got != tc.want {
				t.Errorf("readiness %v, want %v", got, tc.want)
			}
			select {
			case addr := <-received:
				if addr != "192.0.2.7:16968\n" {
					t.Errorf("unexpected request: %q", addr)
				}
			case <-time.After(time.Second):
				t.Fatal("broker did not receive request")
			}
		})
	}
}
