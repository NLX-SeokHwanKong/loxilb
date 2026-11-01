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

package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	MetricQuicCidRouted     = "loxilb_quic_cid_routed_total"
	MetricQuicCidUnroutable = "loxilb_quic_cid_unroutable_total"
	MetricQuicCidMiss       = "loxilb_quic_cid_miss_total"
)

var (
	quicCidRoutedDesc = prometheus.NewDesc(MetricQuicCidRouted,
		"New flows of a quic-cid rule sent to the end-point named by their server ID.", []string{"rule"}, nil)
	quicCidUnroutableDesc = prometheus.NewDesc(MetricQuicCidUnroutable,
		"New flows of a quic-cid rule with no usable server ID, which took the hash path.", []string{"rule"}, nil)
	quicCidMissDesc = prometheus.NewDesc(MetricQuicCidMiss,
		"New flows of a quic-cid rule whose server ID names no active end-point, which took the hash path.", []string{"rule"}, nil)
)

// quicCidCollector reads the selector counters from the datapath at scrape time. They
// are cumulative there, so the exporter keeps no state, and a deleted rule's series go
// with it. Without a quic-cid rule the exposition does not change at all.
type quicCidCollector struct{}

// Describe - implements prometheus.Collector
func (quicCidCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- quicCidRoutedDesc
	ch <- quicCidUnroutableDesc
	ch <- quicCidMissDesc
}

// Collect - implements prometheus.Collector
func (quicCidCollector) Collect(ch chan<- prometheus.Metric) {
	h := hooks
	if h == nil {
		return
	}
	stats, err := h.NetLbQuicCidStatsGet()
	if err != nil {
		return
	}
	for _, s := range stats {
		ch <- prometheus.MustNewConstMetric(quicCidRoutedDesc, prometheus.CounterValue, float64(s.Routed), s.Rule)
		ch <- prometheus.MustNewConstMetric(quicCidUnroutableDesc, prometheus.CounterValue, float64(s.Unroutable), s.Rule)
		ch <- prometheus.MustNewConstMetric(quicCidMissDesc, prometheus.CounterValue, float64(s.Miss), s.Rule)
	}
}

func init() {
	prometheus.MustRegister(quicCidCollector{})
}
