"""Additional correctness trial. Deliberately kept outside the latency sample."""
import json
import socket
import sys

def request(f, owner, vip, port, rid):
    code = """import socket, sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
s.settimeout(5)
s.connect(chr(0)+'loxilb-cid-handoff-v1')
s.sendall(sys.argv[1].encode())
print(s.recv(2048).decode())"""
    return json.loads(f.enter(owner, sys.executable, '-c', code,
                              json.dumps(dict(vip=vip,port=port,rule=rid))))

def select_rule(f, fabric):
    k, v = json.loads(fabric.read('old').rules[0])
    return socket.ntohs(k['dport']), v['ca']['cidx']

def require_rejection(f, name, reply, expected):
    if expected not in reply.get('error', '') or (reply['ct'], reply['fc']) != (0,0):
        raise AssertionError((name, reply))
    f.event('scope_rejection', case=name, reply=reply)

def before(f, fabric):
    port, rid = select_rule(f, fabric)
    require_rejection(f,'live-gates',request(f,'old',f.CID,port,rid),'carrier not confirmed down')
    require_rejection(f,'different-VIP',request(f,'old',f.LEG,port,rid),'invalid handoff scope')

def witnesses(f):
    result = {}
    for table in ('ct_map','fc_v4_map'):
        entries = set()
        for row in f.rows('old',table):
            k, val = row['key'], row['value']
            if k['l4proto'] not in (6,17,132):
                continue
            # The BGP and BFD peers use the front subnet, independently of the VIP.
            if table == 'ct_map':
                addresses = [k[n][0] for n in ('saddr','daddr')]
                stable = val['ca']['cidx']
            else:
                addresses = [k[n] for n in ('saddr','daddr')]
                stable = val['zone']
            if set(addresses) == {f.u32(f.FRONT+'1'),f.u32(f.FRONT+'30')}:
                entries.add((k['l4proto'],json.dumps(k,sort_keys=True),stable))
        result[table] = entries
    return result

def fenced(f, fabric):
    port, rid = select_rule(f, fabric)
    require_rejection(f,'stale-local-rule',request(f,'old',f.CID,port,rid+1),'stale')
    return witnesses(f)

def after(f, fabric, initial):
    port, rid = select_rule(f, fabric)
    reply = request(f,'old',f.CID,port,rid)
    if reply != {'ct':0,'fc':0}:
        raise AssertionError(reply)
    final = witnesses(f)
    for table, entries in initial.items():
        if not entries.issubset(final[table]):
            raise AssertionError(('unrelated entries disappeared',table, len(entries-final[table])))
        f.event('unrelated_survivors',table=table,tcp=sum(k[0]==6 for k in entries),
                udp=sum(k[0]==17 for k in entries),sctp=sum(k[0]==132 for k in entries))
    if {k[0] for k in initial['ct_map']} != {6,17}:
        raise AssertionError('missing live TCP/BGP or UDP/BFD witness')
    f.event('repeat_drain',**reply)
