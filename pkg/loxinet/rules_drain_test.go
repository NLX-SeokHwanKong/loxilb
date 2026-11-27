package loxinet

import (
	"net"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestDrainRequiresMonitoredMvfstV3Rule(t *testing.T) {
	const address = "192.0.2.7"
	const port uint16 = 16968
	key := makeEPKey(address, HostProbeConnectUDP, port)
	previousWake := mh.quicHealthWake
	t.Cleanup(func() { mh.quicHealthWake = previousWake })

	for _, tc := range []struct {
		name       string
		rule       bool
		monitored  bool
		selector   cmn.EpSelect
		profile    string
		targetPort uint16
		drains     bool
	}{
		{name: "no referencing rule"},
		{name: "plain UDP", rule: true, monitored: true, targetPort: port},
		{name: "legacy", rule: true, monitored: true, selector: cmn.LbSelQuicCID, targetPort: port},
		{name: "unmonitored V3", rule: true, selector: cmn.LbSelQuicCID, profile: cmn.QuicLbProfileMvfstV3, targetPort: port},
		{name: "V3 different port", rule: true, monitored: true, selector: cmn.LbSelQuicCID, profile: cmn.QuicLbProfileMvfstV3, targetPort: port + 1},
		{name: "monitored V3", rule: true, monitored: true, selector: cmn.LbSelQuicCID, profile: cmn.QuicLbProfileMvfstV3, targetPort: port, drains: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mh.quicHealthWake = make(chan struct{}, 1)
			ep := &epHost{epKey: key, hostState: cmn.HostStateGreen}
			rules := &RuleH{epMap: map[string]*epHost{key: ep}}
			if tc.rule {
				rules.tables[RtLB].eMap = map[string]*ruleEnt{"rule": {
					hChk: ruleProbe{actChk: tc.monitored},
					act: ruleAct{action: &ruleLBActs{
						sel:         tc.selector,
						quicProfile: tc.profile,
						endPoints:   []ruleLBEp{{xIP: net.ParseIP(address), xPort: tc.targetPort}},
					}},
				}}
			}

			_, err := rules.SetEPHostState(address, port, HostProbeConnectUDP, cmn.HostStateDrain)
			if tc.drains {
				if err != nil || ep.hostState != cmn.HostStateDrain {
					t.Fatalf("state %q, error %v", ep.hostState, err)
				}
				if len(mh.quicHealthWake) != 1 {
					t.Fatal("accepted drain did not wake the health worker")
				}
				if _, err = rules.SetEPHostState(address, port, HostProbeConnectUDP, cmn.HostStateDrain); err != nil {
					t.Fatalf("drain with a wake already queued: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), "monitored mvfst-v3 quic-cid rule") {
				t.Fatalf("unexpected rejection: %v", err)
			}
			if ep.hostState != cmn.HostStateGreen || len(mh.quicHealthWake) != 0 {
				t.Fatalf("rejected drain mutated state %q or queued a wake", ep.hostState)
			}
		})
	}
}
