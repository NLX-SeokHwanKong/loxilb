// SPDX-License-Identifier: Apache-2.0
package loxinet

import "testing"

func TestCIDHandoffRejectsAmbiguousScope(t *testing.T) {
	for _, spec := range []string{"", "198.18.0.1", "::1@a,b", "224.0.0.1@a,b", "198.18.0.1@lo,lo", "198.18.0.1@lo,missing", "198.18.0.1@a,b,c"} {
		if err := startCIDHandoff(spec, 1); err == nil {
			t.Errorf("accepted ambiguous handoff scope %q", spec)
		}
	}
	cfg := cidHandoffConfig{ports: []string{"lo", "nonexistent"}}
	if err := cfg.fenced(); err == nil {
		t.Error("accepted a live or unreadable data port as fenced")
	}
}
