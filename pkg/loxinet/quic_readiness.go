package loxinet

import (
	"io"
	"net"
	"strconv"
	"time"

	"github.com/loxilb-io/loxilb/options"
)

const quicReadinessProbe = "moq-readiness-v1"

func (o epHostOpts) usesQuicReadiness() bool {
	return options.Opts.MoQHealthSocket != "" && o.probeActivated &&
		o.probeType == HostProbeConnectUDP && o.probeReq == quicReadinessProbe
}

func requestQuicReadiness(socket, address string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	conn, err := net.DialTimeout("unix", socket, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	if err = conn.SetDeadline(deadline); err != nil {
		return false
	}
	if _, err = io.WriteString(conn, address+"\n"); err != nil {
		return false
	}
	var result [1]byte
	_, err = io.ReadFull(conn, result[:])
	return err == nil && result[0] == '1'
}

func (ep *epHost) checkQuicReadiness() {
	address := net.JoinHostPort(ep.hostName, strconv.FormatUint(uint64(ep.opts.probePort), 10))
	timeout := time.Duration(options.Opts.MoQHealthTimeoutMS) * time.Millisecond
	ready := requestQuicReadiness(options.Opts.MoQHealthSocket, address, timeout)

	ep.initProberOn = false
	if !ready {
		ep.readinessSuccesses = 0
		ep.transitionEPState(false, ep.opts.inActTryThr)
		return
	}
	ep.inActTries = 0
	if ep.readinessSuccesses < 2 {
		ep.readinessSuccesses++
	}
	if ep.readinessSuccesses >= 2 {
		ep.transitionEPState(true, ep.opts.inActTryThr)
	}
}

// The readiness period is start-to-start. A bounded request occupies only its own
// endpoint slot. Missed scheduling windows do not generate a burst of catch-up probes.
func quicReadinessTicker(r *RuleH, helper int, stop <-chan struct{}) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			r.epMx.Lock()
			for _, endpoint := range r.epMap {
				if endpoint.hID != uint8(helper) || !endpoint.opts.usesQuicReadiness() ||
					endpoint.readinessPending || now.Before(endpoint.readinessDue) {
					continue
				}
				period := time.Duration(endpoint.opts.probeDuration) * time.Second
				if period < time.Second {
					period = time.Second
				}
				endpoint.readinessDue = endpoint.readinessDue.Add(period)
				if !endpoint.readinessDue.After(now) {
					endpoint.readinessDue = now.Add(period)
				}
				endpoint.readinessPending = true
				snapshot := *endpoint
				go func(ep *epHost, probe epHost) {
					r.probeEPHostSnapshot(ep, probe)
					r.epMx.Lock()
					ep.readinessPending = false
					r.epMx.Unlock()
				}(endpoint, snapshot)
			}
			r.epMx.Unlock()
		}
	}
}
