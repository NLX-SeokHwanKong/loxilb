package loxinet

import (
	"net"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestManagedCIDEndpointReconciliation(t *testing.T) {
	a := ruleLBEp{xIP: net.ParseIP("192.0.2.10"), xPort: 16444, weight: 1, epCreated: true}
	b := ruleLBEp{xIP: net.ParseIP("192.0.2.11"), xPort: 16444, weight: 1, epCreated: true}
	c := ruleLBEp{xIP: net.ParseIP("192.0.2.12"), xPort: 16444, weight: 1}

	for _, inactive := range []bool{false, true} {
		b.inActiveEP = inactive
		old := []ruleLBEp{a, b}
		if !inactive {
			if changed, _, _ := getLBConsolidatedEPs(old, []ruleLBEp{a, b}, cmn.LBOPAdd, true); changed {
				t.Fatal("unchanged endpoints require no update")
			}
		}
		changed, kept, removed := getLBConsolidatedEPs(old, []ruleLBEp{a, c}, cmn.LBOPAdd, true)
		if !changed || len(kept) != 2 || len(removed) != 1 {
			t.Fatalf("inactive=%t: got changed=%t kept=%v removed=%v", inactive, changed, kept, removed)
		}
		if !kept[0].xIP.Equal(a.xIP) || !kept[0].epCreated || !kept[1].xIP.Equal(c.xIP) || !removed[0].xIP.Equal(b.xIP) {
			t.Fatalf("survivor, addition and removal mismatch: kept=%v removed=%v", kept, removed)
		}
	}

	_, legacy, _ := getLBConsolidatedEPs([]ruleLBEp{a, b}, []ruleLBEp{a}, cmn.LBOPAdd, false)
	if len(legacy) != 2 || !legacy[1].inActiveEP {
		t.Fatalf("ordinary add must retain inactive arms: %v", legacy)
	}
}
