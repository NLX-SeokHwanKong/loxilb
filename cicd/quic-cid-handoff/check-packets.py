"""Correlate the same TCP data/ACK on the client, promoted peer and backend."""
import json
from pathlib import Path
import socket
import struct
import sys

def packets(path):
    with path.open('rb') as p:
        header=p.read(24)
        endian={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>'}[header[:4]]
        assert struct.unpack_from(endian+'I',header,20)[0]==1
        while block:=p.read(16):
            sec,usec,length,_=struct.unpack(endian+'4I',block)
            b=p.read(length)
            if len(b)<54 or b[12:14]!=b'\x08\x00' or b[23]!=6:continue
            tcp=14+4*(b[14]&15)
            if len(b)<tcp+20:continue
            port,dport,seq,ack=struct.unpack_from('!HHII',b,tcp)
            if 54171 not in (port,dport):continue
            payload=b[tcp+4*(b[tcp+12]>>4):].decode('ascii','replace')
            yield dict(epoch=sec+usec/1e6,smac=b[6:12].hex(':'),dmac=b[:6].hex(':'),
                       src=socket.inet_ntoa(b[26:30]),dst=socket.inet_ntoa(b[30:34]),
                       sport=port,dport=dport,seq=seq,ack=ack,flags=b[tcp+13],data=payload)

def inspect(path):
    run=json.loads((path/'result.json').read_text())
    clock=json.loads((path/'clock.json').read_text())
    fault=clock['epoch']+(run['fault_monotonic']-clock['mono'])
    roles=json.loads(path.with_suffix('.jsonl').read_text().splitlines()[0])
    backup=roles['backup']
    def ps(name):return list(packets(path/(name+'.pcap')))
    client,backend,wire=ps('client'),ps('backend'),ps(backup+'-wire')
    plain=[p for p in client if p['epoch']>=fault and p['sport']==54171 and p['data'].startswith('h')]
    held=run['held']['post']
    if held: target='h'+str(held['seq'])
    else:
        from collections import Counter
        target=Counter(p['data'] for p in plain).most_common(1)[0][0]
    seen=[p for p in plain if p['data']==target]
    assert seen
    seq=seen[0]['seq']; expect=seq+len(target)
    def same(p):return p['data']==target and p['seq']==seq
    def reply(p):return p['data']=='A/'+target and p['ack']==expect
    server_mac=next(p['smac'] for p in backend if p['src']=='198.18.242.20' and p['epoch']<fault and p['sport']==18080)
    translated=[p for p in wire if p['epoch']>=fault and p['dst']=='198.18.242.20' and p['dport']==18080 and same(p)]
    if held: translated=[p for p in translated if p['dmac']==server_mac]
    assert translated
    server=[p for p in backend if p['dmac']==server_mac and p['dst']=='198.18.242.20' and same(p)]
    ack=[p for p in backend if p['src']=='198.18.242.20' and reply(p)]
    rx=[p for p in client if reply(p)]
    syns=[p for p in client if p['sport']==54171 and p['flags']&2]
    assert len(syns)==1 and syns[0]['epoch']<fault
    if held:
        assert server and ack and rx and translated[0]['dmac']==server[0]['dmac']
    else: assert not (server or ack or rx)
    stages={}
    for stage in ('pre','promoted','new-echo','plus3','end'):
        s=json.loads((path/(backup+'-'+stage+'.json')).read_text())
        stages[stage]=[[i for i,a in enumerate(x['value']['fcta']) if a['ca']['act_type']] for x in s['fc_v4_map'] if x['key']['sport']==socket.htons(54171) and x['key']['dport']==socket.htons(18081)]
    return dict(run=path.name,master=roles['master'],backup=backup,standby_ct_keys=run['standby_ct_keys'],promoted_s=run['promoted_s'],new_s=run['new']['fault_to_echo_s'],held_s=run['held'].get('fault_to_echo_s'),held_gap_s=run['held'].get('gap_s'),syn_count=len(syns),held_error=run['held_errors'],payload=target,seq=seq,ack=expect,client_sends=len(seen),first_send=seen[0],backend_mac=server_mac,promoted_wire=translated[0],backend=server[:1],backend_reply=ack[:1],client_reply=rx[:1],forward_fc=stages)
if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect", choices=("kept","lost"))
    parser.add_argument("runs", type=Path, nargs="+")
    args=parser.parse_args()
    for path in args.runs:
        verdict=inspect(path)
        (path/'packet-verdict.json').write_text(json.dumps(verdict,indent=2))
        print(json.dumps(verdict))
        if args.expect:
            survived=verdict['held_s'] is not None
            assert survived == (args.expect=="kept"), verdict
            if survived:
                assert not verdict['held_error']
                assert verdict['forward_fc']['plus3']==[[2,3,5]]
                assert all(3 in actions for stage in verdict['forward_fc'].values() for actions in stage)
