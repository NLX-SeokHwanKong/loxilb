package loxinet

import (
	"net"
	"net/netip"
	"testing"
)

func TestTCPReturnScope(t *testing.T) {
	vip := netip.MustParseAddr("192.0.2.90")
	p := tcpReturnPrep{vips: map[netip.Addr]bool{vip: true}, input: make(chan returnFlow, 1)}
	live := &DpCtInfo{}
	ct := DpCtInfo{ServiceIP: net.ParseIP("192.0.2.91"), SIP: net.ParseIP("198.51.100.12"), Proto: "tcp", ServProto: "tcp"}
	p.offer("test", live, &ct, nil)
	ct.ServiceIP = net.IP(vip.AsSlice())
	for _, proto := range []string{"udp", "sctp"} {
		ct.Proto = proto
		p.offer("test", live, &ct, nil)
	}
	if len(p.input) != 0 {
		t.Fatal("unselected traffic queued")
	}
	ct.Proto = "tcp"
	p.offer("test", live, &ct, nil)
	p.offer("overflow", live, &ct, nil)
	item := <-p.input
	if item.key != "test" || item.ct != live || item.vip != vip || item.client.String() != "198.51.100.12" {
		t.Fatalf("unexpected item %+v", item)
	}
}
