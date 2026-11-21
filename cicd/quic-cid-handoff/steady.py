"""One disposable LoxiLB with routed VIPs and a transparent two-port bridge."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
from contextlib import ExitStack

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root/'fabric'))
spec = importlib.util.spec_from_file_location('fabric', root/'fabric/fabric-trial.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
out = Path(sys.argv[1]).resolve()
out.mkdir()
lb = 'old'
backend = f.BENS[0]
vip = f.LEG
dsr = '198.18.244.12'

def save(name, value):
    (out/name).write_text(json.dumps(value, indent=2))

def launch(stack, args, log):
    stream = stack.enter_context((out/log).open('w'))
    proc = subprocess.Popen(list(map(str,args)),stdout=stream,stderr=subprocess.STDOUT)
    def stop():
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=5)
    stack.callback(stop)
    return proc

def wait(fn):
    for _ in range(100):
        try:
            if fn(): return
        except RuntimeError: pass
        time.sleep(.2)
    raise RuntimeError(f'timed out at {fn}')

def direct(index, ns, peerdev, localdev):
    # Create in the lab switch namespace; both ends leave that namespace.
    x,y = f.TAG+'s'+str(index),f.TAG+'p'+str(index)
    f.n(f.SW,'ip','link','add',x,'type','veth','peer','name',y)
    f.n(f.SW,'ip','link','set',x,'netns',ns)
    f.n(f.SW,'ip','link','set',y,'netns',f.IDS[lb][1])
    f.n(ns,'ip','link','set',x,'name',peerdev)
    f.enter(lb,'ip','link','set',y,'name',localdev)
    f.n(ns,'ip','link','set',peerdev,'up')
    f.enter(lb,'ip','link','set',localdev,'up')

def snap():
    def match(rows): return next(x for x in rows if x['key']['sport']==socket.htons(54771) and x['key']['dport']==socket.htons(18081))
    ct = match(f.rows(lb,'ct_map'))['value']
    fc = match(f.rows(lb,'fc_v4_map'))['value']
    cidx=ct['ca']['cidx']
    raw=json.loads(f.run('bpftool','-j','map','lookup','pinned',f.map_pin(lb,'ct_stats_map'),'key','hex',*[f'{b:02x}' for b in struct.pack('=I',cidx)]))
    values=raw.get('formatted',raw).get('values',[])
    if values and 'packets' in values[0]['value']:
        packets=sum(v['value']['packets'] for v in values)
    else:
        packets=sum(int.from_bytes(bytes(int(x,16) for x in v['value'])[8:16],'little') for v in raw['values'])
    return dict(cidx=cidx,lts=ct['lts'],actions=[i for i,a in enumerate(fc['fcta']) if a['ca']['act_type']],packets=packets,its=fc['its'])

with ExitStack() as stack:
    for ns in (f.SW,f.CLIENT,backend):
        f.run('ip','netns','add',ns)
        stack.callback(f.run,'ip','netns','delete',ns)
        f.n(ns,'ip','link','set','lo','up')
    for br in ('front','back'):
        f.n(f.SW,'ip','link','add',br,'type','bridge')
        f.n(f.SW,'ip','link','set',br,'up')
    f.attach(1,f.CLIENT,'front',f.FRONT+'1','eth0',True)
    f.attach(2,backend,'back',f.A,'eth0',True)
    tag=f.NAMES[lb]=f.TAG+'-steady'
    f.run('docker','run','--pull','never','-d','--network','none','--privileged','--name',tag,'--entrypoint','/bin/sh',f.V7,'-ec','mount --make-rprivate /; until test -f /tmp/q7-ready; do sleep .1; done; exec /root/loxilb-io/loxilb/loxilb --egr-hooks')
    stack.callback(f.run,'docker','rm','-f',tag)
    f.IDS[lb]=f.docker_id(lb)
    for i,(br,prefix,dev) in enumerate((('front',f.FRONT,'eth1'),('back',f.BACK,'eth0'))):
        f.attach(3+i,lb,br,prefix+'30',dev,True,f.IDS[lb][1])
    direct(5,f.CLIENT,'l2test','eth2')
    direct(6,backend,'l2test','eth3')
    f.enter(lb,'ip','link','add','vlan77','type','bridge')
    for dev in ('eth2','eth3'): f.enter(lb,'ip','link','set',dev,'master','vlan77')
    f.enter(lb,'ip','link','set','vlan77','up')
    for ns,addr in ((f.CLIENT,'198.18.246.1/24'),(backend,'198.18.246.2/24')):
        f.n(ns,'ip','addr','add',addr,'dev','l2test')
    f.enter(lb,'ip','addr','add',vip+'/32','dev','eth1')
    f.run('docker','exec',tag,'touch','/tmp/q7-ready')
    wait(lambda:f.api(lb,'GET','/all'))
    wait(lambda:all('bpf' in f.enter(lb,'tc','filter','show','dev',dev,'ingress') for dev in ('eth0','eth1','eth2','eth3')))
    for proto,(_,port) in f.PORTS.items(): f.setup_rule(lb,vip,proto,port,[f.A])
    f.api(lb,'POST',body=dict(serviceArguments=dict(externalIP=vip,port=5201,protocol='tcp',mode=2,sel=0),endpoints=[dict(endpointIP=f.A,targetPort=5201,weight=1)]))
    for ns,via in ((f.CLIENT,f.FRONT+'30'),(backend,f.BACK+'30')):f.n(ns,'ip','route','add',vip+'/32','via',via)
    launch(stack,['ip','netns','exec',backend,'python3',root/'fabric/echo.py','A'],'echo.log')
    launch(stack,['ip','netns','exec',backend,'iperf3','-s','-B',f.A],'iperf-server.log')
    wait(lambda:f.result(f.CLIENT,vip,6,18081)=='A')
    client_code="""import socket,sys,time
from pathlib import Path
d=Path(sys.argv[2])
s=socket.socket();s.settimeout(5);s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);s.bind(('',54771));s.connect((sys.argv[1],18081))
def echo(i):
 b=('%08d'%i).encode();s.sendall(b);r=b''
 while len(r)<10:
  v=s.recv(10-len(r));assert v;r+=v
 assert r==b'A/'+b
for i in range(20):echo(i)
(d/'ready').touch()
while not (d/'go').exists():time.sleep(.01)
for i in range(1000):echo(i)
(d/'done').touch()
while True:time.sleep(.1)
"""
    launch(stack,['ip','netns','exec',f.CLIENT,'python3','-c',client_code,vip,out],'warm-client.log')
    wait(lambda:(out/'ready').exists())
    time.sleep(.15)
    before=snap()
    (out/'go').touch()
    wait(lambda:(out/'done').exists())
    time.sleep(.15)
    after=snap()
    save('warm.json',dict(image=f.V7,before=before,after=after,echoes=1000))
    # Every slow CT hit updates lts. The same installed FC and an advancing
    # directional counter with unchanged lts identify a fully warm interval.
    assert before['cidx']==after['cidx'] and before['its']==after['its']
    assert before['actions']==after['actions']==[2,3,5]
    assert before['lts']==after['lts'] and after['packets']-before['packets']>=1000
    f.event('warm',before=before,after=after)
    for i in range(int(os.getenv('ROUNDS','3'))):
        run=json.loads(f.n(f.CLIENT,'iperf3','-c',vip,'-t','6','-O','1','-J'))
        save(f'iperf-{i}.json',run)
        f.event('goodput',bps=run['end']['sum_received']['bits_per_second'])
    got={proto:[f.result(f.CLIENT,vip,num,port) for _ in range(4)] for proto,(num,port) in f.PORTS.items()}
    l2=[f.result(f.CLIENT,'198.18.246.2',6,18080) for _ in range(10)]
    fdb=f.enter(lb,'bridge','fdb','show','br','vlan77')
    macs=[f.n(ns,'cat','/sys/class/net/l2test/address') for ns in (f.CLIENT,backend)]
    # Static FDBs ensure the eBPF bridge also has deterministic local entries.
    for dev,mac in zip(('eth2','eth3'),macs):f.enter(lb,'bridge','fdb','replace',mac,'dev',dev,'master','static')
    for _ in range(4):f.result(f.CLIENT,'198.18.246.2',6,18080)
    dmac=f.rows(lb,'dmac_map')
    installed={bytes(r['key']['dmac']).hex(':') for r in dmac if r['key']['bd']==77}
    assert set(macs)<=installed
    save('l2.json',dict(echo=l2,fdb=fdb,macs=macs,dmac_map=dmac,hooks={dev:f.enter(lb,'tc','-s','filter','show','dev',dev,'ingress') for dev in ('eth2','eth3')}))
    assert all(samples==['A']*4 for samples in got.values()) and l2==['A']*10
    f.event('legacy',got=got,l2=l2)
    # Dedicated bypass for DSR replies, independent of the bridge and of the LB.
    x,y=f.TAG+'da',f.TAG+'db'
    f.n(f.SW,'ip','link','add',x,'type','veth','peer','name',y)
    for ns,dev,addr in ((backend,x,'198.18.247.2/30'),(f.CLIENT,y,'198.18.247.1/30')):
        f.n(f.SW,'ip','link','set',dev,'netns',ns)
        f.n(ns,'ip','link','set',dev,'name','direct0')
        f.n(ns,'ip','addr','add',addr,'dev','direct0'); f.n(ns,'ip','link','set','direct0','up')
    for ns in (backend,f.CLIENT):
        for dev in ('all','eth0','direct0'):f.n(ns,'sysctl','-qw','net.ipv4.conf.'+dev+'.rp_filter=0')
    f.n(backend,'ip','route','add',f.FRONT+'1/32','via','198.18.247.1')
    f.n(backend,'ip','addr','add',dsr+'/32','dev','lo')
    f.n(f.CLIENT,'ip','route','add',dsr+'/32','via',f.FRONT+'30')
    f.api(lb,'POST',body=dict(serviceArguments=dict(externalIP=dsr,port=18080,protocol='tcp',mode=3,sel=1),endpoints=[dict(endpointIP=f.A,targetPort=18080,weight=1)]))
    cap=launch(stack,['ip','netns','exec',f.CLIENT,'tcpdump','--immediate-mode','-l','-n','-i','direct0','src','host',dsr,'and','tcp','src','port','18080'],'dsr-return.log')
    wait(lambda:'listening on' in (out/'dsr-return.log').read_text())
    wait(lambda:f.result(f.CLIENT,dsr,6,18080)=='A')
    ds=[f.result(f.CLIENT,dsr,6,18080) for _ in range(10)]
    assert ds==['A']*10
    assert '.18080 > ' in (out/'dsr-return.log').read_text()
    save('services.json',dict(image=f.V7,legacy=got,l2=l2,dsr=ds,return_route=f.n(backend,'ip','route','get',f.FRONT+'1'),rules=f.rows(lb,'nat_map')))
    f.event('dsr',echo=ds)
