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
	"errors"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)
 
 const (
	 POL_ERR_BASE = iota - 100000
	 POL_MOD_ERR
	 POL_INFO_ERR
	 POL_ATTACH_ERR
	 POL_NOEXIST_ERR
	 POL_EXISTS_ERR
	 POL_ALLOC_ERR
 )
 
 const (
	 MIN_ROL_RATE     = 8
	 MAX_POLS    	  = 8*1024
	 DFL_POL_BLK_SZ   = 6*5000*1000
 )

 type PolKey struct {
	 PolName string
 }
 
 type PolStats struct {
	 PacketsOk  uint64
	 PacketsNok uint64
 }

 type PolAttachObjT interface {
 }

 type PolObjInfo struct {
	Args		 cmn.PolObj
	AttachObj    PolAttachObjT
	Parent	     *PolEntry
	Sync         DpStatusT
 }
 
 type PolEntry struct {
	 Key    PolKey
	 Info   cmn.PolInfo
	 Zone   *Zone
	 HwNum  int
	 Stats  PolStats
	 Sync   DpStatusT
	 PObjs  []PolObjInfo
 }
 
 type PolH struct {
	 PolMap  map[PolKey]*PolEntry
	 Zone    *Zone
	 HwMark  *tk.Counter
 }
 
 func PolInit(zone *Zone) *PolH {
	 var nPh = new(PolH)
	 nPh.PolMap = make(map[PolKey]*PolEntry)
	 nPh.Zone = zone
	 nPh.HwMark = tk.NewCounter(1, MAX_POLS)
	 return nPh
 }

 func PolInfoXlateValidate(pInfo *cmn.PolInfo) (bool) {
	if pInfo.CommittedInfoRate < MIN_ROL_RATE {
		return false
	}

	if pInfo.PeakInfoRate < MIN_ROL_RATE {
		return false
	}

	pInfo.CommittedInfoRate = pInfo.CommittedInfoRate*1000000
	pInfo.PeakInfoRate = pInfo.PeakInfoRate*1000000

	if pInfo.CommittedBlkSize == 0 {
		pInfo.CommittedBlkSize = DFL_POL_BLK_SZ
		pInfo.ExcessBlkSize = 2*DFL_POL_BLK_SZ
	} else {
		pInfo.ExcessBlkSize = 2*pInfo.CommittedBlkSize
	}
	return true
 }

 func PolObjValidate(pObj *cmn.PolObj) (bool) {

	if pObj.AttachMent != cmn.POL_ATTACH_PORT && pObj.AttachMent != cmn.POL_ATTACH_LB_RULE {
		return false
	}

	return true
 }

 // Add a policer in loxinet
func (P *PolH) PolAdd(pName string, pInfo cmn.PolInfo, pObjArgs cmn.PolObj) (int, error) {

	if PolObjValidate(&pObjArgs) == false {
		tk.LogIt(tk.LOG_ERROR, "policer add - %s: bad attach point\n", pName)
		return POL_ATTACH_ERR, errors.New("pol-attachpoint error")
	}

	if PolInfoXlateValidate(&pInfo) == false {
		tk.LogIt(tk.LOG_ERROR, "policer add - %s: info error\n", pName)
		return POL_INFO_ERR, errors.New("pol-info error")
	}

	key := PolKey{pName}
	p, found := P.PolMap[key]

	if found == true {
		if p.Info != pInfo {
			P.PolDelete(pName)
		} else {
			return POL_EXISTS_ERR, errors.New("pol-exists error")
		}
	}

	p = new(PolEntry)
	p.Key.PolName = pName
	p.Info = pInfo
	p.Zone = P.Zone
	p.HwNum, _ = P.HwMark.GetCounter()
	if p.HwNum < 0 {
		return POL_ALLOC_ERR, errors.New("pol-alloc error")
	}

	pObjInfo := PolObjInfo { Args:pObjArgs }
	pObjInfo.Parent = p

	P.PolMap[key] = p

	p.DP(DP_CREATE)
	pObjInfo.PolObj2DP(DP_CREATE)

	p.PObjs = append(p.PObjs, pObjInfo)

	tk.LogIt(tk.LOG_INFO, "policer added - %s\n", pName)

	return 0, nil
}

 // Delete a policer from loxinet
func (P *PolH) PolDelete(pName string) (int, error) {

	key := PolKey{pName}
	p, found := P.PolMap[key]

	if found == false {
		tk.LogIt(tk.LOG_ERROR, "policer delete - %s: not found error\n", pName)
		return POL_NOEXIST_ERR, errors.New("no such policer error")
	}

	for idx, pObj := range p.PObjs {
		var pP *PolObjInfo = &p.PObjs[idx]
		pObj.PolObj2DP(DP_REMOVE)
		pP.Parent = nil
	}

	p.DP(DP_REMOVE)

	delete(P.PolMap, p.Key)

	tk.LogIt(tk.LOG_INFO, "policer deleted - %s\n", pName)

	return 0, nil
}

func (P *PolH) PolPortDelete(name string) {
	for _, p := range P.PolMap {
		for idx, pObj := range p.PObjs {
			var pP *PolObjInfo
			if pObj.Args.AttachMent == cmn.POL_ATTACH_PORT &&
				pObj.Args.PolObjName == name {
				pP = &p.PObjs[idx]
				pP.Sync = 1
			}
		}
	}
}

func (P *PolH) PolDestructAll() {
	for _, p := range P.PolMap {
		P.PolDelete(p.Key.PolName)
	}
}

func (P *PolH) PolTicker() {
	for _, p := range P.PolMap {
		if p.Sync != 0 {
			p.DP(DP_CREATE)
			for _, pObj := range p.PObjs {
				pObj.PolObj2DP(DP_CREATE)
			}
		} else {
			for idx, pObj := range p.PObjs {
				var pP *PolObjInfo
				pP = &p.PObjs[idx]
				if pP.Sync != 0 {
					pP.PolObj2DP(DP_CREATE)
				} else {
					if pObj.Args.AttachMent == cmn.POL_ATTACH_PORT {
						port := pObj.Parent.Zone.Ports.PortFindByName(pObj.Args.PolObjName)
						if port == nil {
							pP.Sync = 1
						}
					}
				}
			}
		}
	}
}

// Sync state of policer's attachment point with data-path
func (pObjInfo *PolObjInfo) PolObj2DP(work DpWorkT) int {

	// Only port attachment is supported currently
	if pObjInfo.Args.AttachMent != cmn.POL_ATTACH_PORT {
		return -1
	}

	port := pObjInfo.Parent.Zone.Ports.PortFindByName(pObjInfo.Args.PolObjName)
	if port == nil {
		pObjInfo.Sync = 1
		return -1
	}

	if work == DP_CREATE {
		_, err:= pObjInfo.Parent.Zone.Ports.PortUpdateProp(port.Name, cmn.PORT_PROP_POL,
			pObjInfo.Parent.Zone.Name, true, pObjInfo.Parent.HwNum)
		if err != nil {
			pObjInfo.Sync = 1
			return -1
		}
	} else if work == DP_REMOVE {
		pObjInfo.Parent.Zone.Ports.PortUpdateProp(port.Name, cmn.PORT_PROP_POL,
			pObjInfo.Parent.Zone.Name, false, 0)
	}

	pObjInfo.Sync = 0

	return 0
}

// Sync state of policer with data-path
func (p *PolEntry) DP(work DpWorkT) int {

	pwq := new(PolDpWorkQ)
	pwq.Work = work
	pwq.HwMark = p.HwNum
	pwq.Color = p.Info.ColorAware
	pwq.Cir = p.Info.CommittedInfoRate
	pwq.Pir = p.Info.PeakInfoRate
	pwq.Cbs = p.Info.CommittedBlkSize
	pwq.Ebs = p.Info.ExcessBlkSize
	pwq.Status = &p.Sync

	mh.dp.ToDpCh <- pwq

	return 0
}