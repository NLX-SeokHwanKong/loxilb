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
package loxinlp

import (
	"slices"
	"testing"
	"time"

	nlp "github.com/vishvananda/netlink"
)

func TestRunNetlinkUpdates(t *testing.T) {
	type applied struct {
		kind  string
		index int
	}

	cases := []struct {
		name string
		want []applied
	}{
		{
			name: "pending_links_first",
			want: []applied{{"link", 11}, {"link", 12}, {"address", 21}, {"neighbour", 31}, {"route", 41}},
		},
		{name: "closed_channels_emit_nothing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := &NlH{}
			n.FromLUCh = make(chan nlp.LinkUpdate, 2)
			n.FromAUCh = make(chan nlp.AddrUpdate, 1)
			n.FromNUCh = make(chan nlp.NeighUpdate, 1)
			n.FromRUCh = make(chan nlp.RouteUpdate, 1)

			if len(tc.want) != 0 {
				// Make all four channels ready before the worker's first select.
				for _, index := range []int{11, 12} {
					n.FromLUCh <- nlp.LinkUpdate{Link: &nlp.Dummy{LinkAttrs: nlp.LinkAttrs{Index: index}}}
				}
				n.FromAUCh <- nlp.AddrUpdate{LinkIndex: 21}
				n.FromNUCh <- nlp.NeighUpdate{Neigh: nlp.Neigh{LinkIndex: 31}}
				n.FromRUCh <- nlp.RouteUpdate{Route: nlp.Route{LinkIndex: 41}}
			}
			close(n.FromLUCh)
			close(n.FromAUCh)
			close(n.FromNUCh)
			close(n.FromRUCh)

			var got []applied
			record := func(kind string, index int) int {
				got = append(got, applied{kind, index})
				return 0
			}
			done := make(chan struct{})
			go func() {
				runNetlinkUpdates(n,
					func(update nlp.LinkUpdate) int {
						if update.Link == nil {
							return record("link", 0)
						}
						return record("link", update.Link.Attrs().Index)
					},
					func(update nlp.AddrUpdate) int { return record("address", update.LinkIndex) },
					func(update nlp.NeighUpdate) int { return record("neighbour", update.LinkIndex) },
					func(update nlp.RouteUpdate) int { return record("route", update.LinkIndex) },
				)
				close(done)
			}()

			select {
			case <-done:
				if !slices.Equal(got, tc.want) {
					t.Errorf("applied updates = %v, want %v", got, tc.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("worker did not exit after all update channels closed")
			}
		})
	}
}
