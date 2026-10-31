/*
 * Copyright (c) 2022 NetLOX Inc
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
	"fmt"
)

// This file implements the interface DpHookInterface
// The implementation is specific to loxilb ebpf datapath for windows (in-progress)

const (
	EBPF_ERR_BASE = iota - DP_ERR_BASE - 1000
)

type DpEbpfH struct {
}

// DpQuicCidAvail - tells whether the datapath has the QUIC CID selector
func DpQuicCidAvail() bool {
	return false
}

// DpQuicCidStatsGet - reads the selector counters of a rule by its mark
func DpQuicCidStatsGet(mark int) (routed, unroutable, miss uint64, ok bool) {
	return 0, 0, 0, false
}

// DpQuicCidStatsClear - zeroes the selector counters of a rule by its mark
func DpQuicCidStatsClear(mark int) {
}

func DpEbpfInit() *DpEbpfH {
	ne := new(DpEbpfH)
	return ne
}

func SysctlInit() {

}

func SysctlPostInit() {
}
