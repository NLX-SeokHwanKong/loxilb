/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package loxinet

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestValidateQuicCidRule(t *testing.T) {
	eps := []cmn.LbEndPointArg{{EpIP: "10.0.0.1"}, {EpIP: "10.0.0.2"}}
	good := cmn.LbServiceArg{ServIP: "20.0.0.1", Proto: "udp", Sel: cmn.LbSelQuicCID}

	tests := []struct {
		name   string
		mod    func(*cmn.LbServiceArg)
		eps    []cmn.LbEndPointArg
		ok     bool
		sidLen uint8
		cr     uint8
	}{
		{name: "defaults", mod: func(s *cmn.LbServiceArg) {}, ok: true, sidLen: 4},
		{name: "onearm", mod: func(s *cmn.LbServiceArg) { s.Mode = cmn.LBModeOneArm }, ok: true, sidLen: 4},
		{name: "fullnat", mod: func(s *cmn.LbServiceArg) { s.Mode = cmn.LBModeFullNAT }, ok: true, sidLen: 4},
		{name: "hostonearm", mod: func(s *cmn.LbServiceArg) { s.Mode = cmn.LBModeHostOneArm; s.ServIP = "0.0.0.0" }, ok: true, sidLen: 4},
		{name: "explicit", mod: func(s *cmn.LbServiceArg) { s.QuicLb = &cmn.QuicLbArg{SidLen: 4, Cr: 7} }, ok: true, sidLen: 4, cr: 7},
		{name: "dsr", mod: func(s *cmn.LbServiceArg) { s.Mode = cmn.LBModeDSR }},
		{name: "fullproxy", mod: func(s *cmn.LbServiceArg) { s.Mode = cmn.LBModeFullProxy }},
		{name: "tcp", mod: func(s *cmn.LbServiceArg) { s.Proto = "tcp" }},
		{name: "sctp", mod: func(s *cmn.LbServiceArg) { s.Proto = "sctp" }},
		{name: "snat", mod: func(s *cmn.LbServiceArg) { s.Snat = true }},
		{name: "egress", mod: func(s *cmn.LbServiceArg) { s.Egress = true }},
		{name: "ppv2", mod: func(s *cmn.LbServiceArg) { s.ProxyProtocolV2 = true }},
		{name: "v6 vip", mod: func(s *cmn.LbServiceArg) { s.ServIP = "2001:db8::1" }},
		{name: "sidLen 0", mod: func(s *cmn.LbServiceArg) { s.QuicLb = &cmn.QuicLbArg{SidLen: 0} }},
		{name: "sidLen 3", mod: func(s *cmn.LbServiceArg) { s.QuicLb = &cmn.QuicLbArg{SidLen: 3} }},
		{name: "sidLen 5", mod: func(s *cmn.LbServiceArg) { s.QuicLb = &cmn.QuicLbArg{SidLen: 5} }},
		{name: "cr 8", mod: func(s *cmn.LbServiceArg) { s.QuicLb = &cmn.QuicLbArg{SidLen: 4, Cr: 8} }},
		{name: "v6 ep", mod: func(s *cmn.LbServiceArg) {}, eps: []cmn.LbEndPointArg{{EpIP: "2001:db8::2"}}},
		{name: "dup ep", mod: func(s *cmn.LbServiceArg) {}, eps: []cmn.LbEndPointArg{{EpIP: "10.0.0.1"}, {EpIP: "10.0.0.1", EpPort: 8443}}},
	}
	for _, tc := range tests {
		s := good
		tc.mod(&s)
		e := eps
		if tc.eps != nil {
			e = tc.eps
		}
		sidLen, cr, err := validateQuicCidRule(&s, e)
		if tc.ok != (err == nil) {
			t.Errorf("%s: err %v, want ok %v", tc.name, err, tc.ok)
		}
		if tc.ok && (sidLen != tc.sidLen || cr != tc.cr) {
			t.Errorf("%s: got sidLen %d cr %d", tc.name, sidLen, cr)
		}
	}
}
