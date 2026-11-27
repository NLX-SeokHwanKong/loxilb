"""Decode native IPv4 FullNAT CID rules and guard values for an exclusive VIP."""
import json
import socket
import struct
from collections import Counter
from handoff import Hold, View

def u32(addr):
    return struct.unpack('=I',socket.inet_aton(addr))[0]

def native_view(ident, vip, nat, guards):
    expected=Counter()
    rules=[]
    for row in nat:
        k,v=row['key'],row['value']
        if (k['daddr']!=[u32(vip),0,0,0] or k['zone']!=1 or k['l4proto']!=17
                or k['v6'] or v['sel_type']!=7 or v['opflags']!=2 or v['ca']['act_type']!=2):
            raise Hold('only dedicated IPv4 FullNAT CID rules supported')
        keys=set()
        for ep in v['nxfrms'][:v['nxfrm']]:
            if ep['nat_xip'][0] and ep['nat_rip'][0]:
                if ep['nat_rip'][0]!=u32(vip) or ep['nv6']:
                    raise Hold('unexpected return address')
                keys.add((u32(vip),ep['nat_xip'][0],ep['nat_xport'] or k['dport'],k['zone']))
        expected.update(keys)
        # Keep stable forwarding config, omit only changing selection hints/time.
        for field in ('sel_hint','lts','lock'):
            v.pop(field,None)
        rules.append(json.dumps([k,v],sort_keys=True))
    guard={}
    for row in guards:
        k=row['key']
        key=tuple(k[i] for i in ('vip','backend','sport','zone'))
        if key[0]!=u32(vip) or key[-1]!=1:
            raise Hold('mixed VIP or zone')
        guard[key]=row['value']
    return View(ident,tuple(sorted(rules)),dict(expected),guard)


def drained(vip, rows):
    addr=u32(vip)
    return not any(k['zone']==1 and k['l4proto']==17 and addr in (k['saddr'][0],k['daddr'][0])
                   for k in (r['key'] for r in rows))
