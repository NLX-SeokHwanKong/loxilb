package loxinet

import (
	"net"
	"net/netip"
	"sync"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	tk "github.com/loxilb-io/loxilib"
	nlp "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	returnCapacity = 256
	returnInterval = 100 * time.Millisecond
	returnRefresh  = 30 * time.Second
)

type returnFlow struct {
	key         string
	ct          *DpCtInfo
	rule        *ruleEnt
	vip, client netip.Addr
	service     cmn.LbServiceArg
}

type returnHop struct {
	addr netip.Addr
	link int
}

type tcpReturnPrep struct {
	dp         *DpEbpfH
	vips       map[netip.Addr]bool
	input      chan returnFlow
	quit, done chan struct{}
	once       sync.Once
}

func newTCPReturnPrep(dp *DpEbpfH) *tcpReturnPrep {
	if len(opts.Opts.TCPReturnVIPs) == 0 {
		return nil
	}
	p := &tcpReturnPrep{dp: dp, vips: make(map[netip.Addr]bool), input: make(chan returnFlow, returnCapacity), quit: make(chan struct{}), done: make(chan struct{})}
	for _, vip := range opts.Opts.TCPReturnVIPs {
		p.vips[netip.MustParseAddr(string(vip))] = true
	}
	go p.run()
	return p
}

func (p *tcpReturnPrep) stop() {
	p.once.Do(func() { close(p.quit) })
	<-p.done
}

// offer runs only after a forward CT was installed by XSync. It never waits
// for a route lookup, neighbor discovery or space in the worker queue.
func (p *tcpReturnPrep) offer(key string, live, ct *DpCtInfo, rule *ruleEnt) {
	vip, _ := netip.AddrFromSlice(ct.ServiceIP.To4())
	client, _ := netip.AddrFromSlice(ct.SIP.To4())
	if !p.vips[vip] || !client.IsGlobalUnicast() || ct.ServProto != "tcp" || ct.Proto != "tcp" {
		return
	}
	flow := returnFlow{key: key, ct: live, rule: rule, vip: vip, client: client, service: cmn.LbServiceArg{ServIP: vip.String(), Proto: "tcp", ServPort: ct.L4ServPort, ServPortMax: ct.L4ServPortMax, BlockNum: ct.BlockNum}}
	select {
	case p.input <- flow:
	default:
	}
}

func (p *tcpReturnPrep) eligible(f returnFlow) bool {
	p.dp.mtx.RLock()
	live := p.dp.ctMap[f.key] == f.ct && f.ct.Deleted == 0 && f.ct.CState == "est"
	p.dp.mtx.RUnlock()
	if !live {
		return false
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()
	r := mh.zr.Rules.GetLBRuleByServArgs(f.service)
	if r == nil || r != f.rule || r.tuples.l4Prot.val != unix.IPPROTO_TCP || !r.tuples.l3Dst.addr.IP.Equal(net.IP(f.vip.AsSlice())) {
		return false
	}
	act, ok := r.act.action.(*ruleLBActs)
	if !ok || act.mode != cmn.LBModeFullNAT {
		return false
	}
	role, _ := mh.has.CIStateGetInst(r.ci)
	return role == cmn.CIBackupStateString
}

func localReturnHop(client netip.Addr) (returnHop, bool) {
	routes, err := nlp.RouteGet(net.IP(client.AsSlice()))
	if err != nil || len(routes) != 1 {
		return returnHop{}, false
	}
	r := routes[0]
	if r.Type != unix.RTN_UNICAST || r.LinkIndex <= 0 || len(r.MultiPath) != 0 || r.Encap != nil || r.Via != nil {
		return returnHop{}, false
	}
	hop := client
	if r.Gw != nil {
		hop, _ = netip.AddrFromSlice(r.Gw.To4())
	}
	return returnHop{hop, r.LinkIndex}, hop.Is4() && hop.IsGlobalUnicast()
}

// A single link-local ICMP echo asks the kernel to resolve a missing neighbor.
// Bind the outgoing interface and forbid gateway forwarding. No peer MAC,
// static neighbor, route or VIP address is written.
func probeReturnHop(h returnHop) error {
	link, err := net.InterfaceByIndex(h.link)
	if err != nil {
		return err
	}
	if link.Flags&net.FlagUp == 0 || link.Flags&net.FlagLoopback != 0 || len(link.HardwareAddr) != 6 {
		return nil
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, link.Name); err != nil {
		return err
	}
	if err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, 1); err != nil {
		return err
	}
	// Echo request, empty body, identifier and sequence zero, Internet checksum.
	return unix.Sendto(fd, []byte{8, 0, 0xf7, 0xff, 0, 0, 0, 0}, unix.MSG_DONTROUTE, &unix.SockaddrInet4{Addr: h.addr.As4()})
}

func (p *tcpReturnPrep) run() {
	defer close(p.done)
	tick := time.NewTicker(returnInterval)
	defer tick.Stop()
	type entry struct {
		flow returnFlow
		next time.Time
	}
	pending := make(map[string]entry)
	recent := make(map[returnHop]time.Time)
	for {
		select {
		case <-p.quit:
			return
		case f := <-p.input:
			if item, ok := pending[f.key]; ok || len(pending) < returnCapacity {
				if item.flow.ct != f.ct || item.flow.rule != f.rule {
					item.next = time.Time{}
				}
				item.flow = f
				pending[f.key] = item
			}
		case now := <-tick.C:
			var chosen string
			for key, item := range pending {
				if item.next.After(now) {
					continue
				}
				if chosen == "" || item.next.Before(pending[chosen].next) {
					chosen = key
				}
			}
			if chosen == "" {
				continue
			}
			item := pending[chosen]
			f := item.flow
			if !p.eligible(f) {
				delete(pending, chosen)
				continue
			}
			item.next = now.Add(returnRefresh)
			pending[chosen] = item
			h, ok := localReturnHop(f.client)
			if !ok || now.Before(recent[h]) {
				continue
			}
			for key, until := range recent {
				if !now.Before(until) {
					delete(recent, key)
				}
			}
			recent[h] = now.Add(returnRefresh)
			mh.mtx.Lock()
			neigh, _ := mh.zr.Nh.NeighFind(net.IP(h.addr.AsSlice()), RootZone, h.link)
			ready := neigh != nil && neigh.Resolved && !neigh.Inactive && !neigh.Dummy
			mh.mtx.Unlock()
			if !ready && p.eligible(f) {
				if err := probeReturnHop(h); err != nil {
					tk.LogIt(tk.LogDebug, "TCP return probe %s on ifindex %d: %v\n", h.addr, h.link, err)
				}
			}
		}
	}
}
