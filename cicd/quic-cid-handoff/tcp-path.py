"""Dedicated single-host L2 FullNAT lab. Both service ownership and VIP advertisement are native."""
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

here = Path(__file__).resolve().parent
sys.path.insert(0,str(here/'fabric'))
spec = importlib.util.spec_from_file_location('fabric',here/'fabric/fabric-trial.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
out = Path(sys.argv[1]).resolve()
out.mkdir()
vip, backend, client = f.FRONT+'90', f.FRONT+'20', f.FRONT+'1'

def api(owner, path):
    return json.loads(f.enter(owner,'curl','-fsS','--max-time','2','http://127.0.0.1:11111/netlox/v1/config/'+path))

def state(owner):
    return next(x['state'] for x in api(owner,'cistate/all')['Attr'] if x['instance']=='llb-inst0')

def snapshot(path,data):
    (out/path).write_text(json.dumps(data,indent=2))

def wait(predicate, timeout):
    end = time.monotonic()+timeout
    while time.monotonic()<end:
        if predicate():
            return
        time.sleep(.1)
    raise RuntimeError('timeout waiting for '+predicate.__name__)

def proc(stack, cmd, filename):
    log = stack.enter_context((out/filename).open('w'))
    p = subprocess.Popen(list(map(str,cmd)),stdout=log,stderr=subprocess.STDOUT)
    def stop():
        p.terminate()
        p.wait(timeout=5)
    stack.callback(stop)
    return p

def keep_logs(owner):
    (out/(owner+'.log')).write_text(f.run('docker','logs',f.NAMES[owner])+'\n')
    # LoxiLB also writes its detailed logs to /var/log.
    result=subprocess.run(['docker','exec',f.NAMES[owner],'sh','-c','tail -250 /var/log/loxilb*.log'],capture_output=True,text=True)
    (out/(owner+'-tail.log')).write_text(result.stdout)

def probes():
    return [json.loads(l) for l in (out/'probe.jsonl').read_text().splitlines() if l.startswith('{') and l.endswith('}')]

with ExitStack() as stack:
    for ns in (f.SW,f.CLIENT,f.BENS[0]):
        f.run('ip','netns','add',ns)
        stack.callback(f.run,'ip','netns','delete',ns)
        f.n(ns,'ip','link','set','lo','up')
    for bridge in ('lan','sync'):
        f.n(f.SW,'ip','link','add',bridge,'type','bridge')
        f.n(f.SW,'ip','link','set',bridge,'up')
    f.attach(1,f.CLIENT,'lan',client,'eth0',True)
    f.attach(2,f.BENS[0],'lan',backend,'eth0',True)
    proc(stack,['ip','netns','exec',f.BENS[0],'python3',here/'fabric/echo.py','A'],'server.log')
    for i,owner in enumerate(('old','new')):
        addr_idx = 1-i if os.getenv("FLIP") else i
        idx, peer = str(30+addr_idx), str(31-addr_idx)
        name=f.NAMES[owner]=f.TAG+'-'+owner
        args=['--egr-hooks','--self='+str(i),'--cluster='+f.BACK+peer]
        f.run('docker','run','--pull','never','-d','--network','none','--privileged','--name',name,'--entrypoint','/bin/sh',f.V7,'-ec',
              'mount --make-rprivate /; until test -f /tmp/q7-ready; do sleep .1; done; exec /root/loxilb-io/loxilb/loxilb "$@"','sh',*args)
        stack.callback(f.run,'docker','rm','-f',name)
        stack.callback(keep_logs,owner)
        f.IDS[owner]=f.docker_id(owner)
        f.PORT[owner]=[f.attach(3+i*2+j,owner,br,prefix+idx,dev,True,f.IDS[owner][1])
                       for j,(br,prefix,dev) in enumerate([('lan',f.FRONT,'eth1'),('sync',f.BACK,'eth0')])]
    for owner in f.IDS:
        f.run('docker','exec',f.NAMES[owner],'touch','/tmp/q7-ready')
        def api_ready():
            try:
                state(owner)
                return ':3784' in f.enter(owner,'ss','-uln')
            except (RuntimeError, StopIteration, KeyError):
                return False
        wait(api_ready,40)
    for i,owner in enumerate(f.IDS):
        addr_idx = 1-i if os.getenv("FLIP") else i
        body=dict(instance='llb-inst0',sourceIp=f.BACK+str(30+addr_idx),remoteIp=f.BACK+str(31-addr_idx),interval=200000,retryCount=3)
        res=f.enter(owner,'curl','-fsS','-H','Content-Type: application/json','-d',json.dumps(body),'http://127.0.0.1:11111/netlox/v1/config/bfd')
        assert json.loads(res).get('result')=='Success',res
    def elected():
        try:
            states={x:state(x) for x in f.IDS}
            return set(states.values())=={'MASTER','BACKUP'} and all('BFDUp' in str(api(x,'bfd/all')) for x in f.IDS)
        except (RuntimeError,StopIteration): return False
    wait(elected,150)
    master=next(x for x in f.IDS if state(x)=='MASTER')
    backup=next(x for x in f.IDS if x!=master)
    for owner in f.IDS:
        status=api(owner,'bfd/all')
        snapshot(owner+'-bfd.json',status)
        assert status['Attr'][0]['interval']==200000 and status['Attr'][0]['retryCount']==3,status
        f.setup_rule(owner,vip,'tcp',18081,[backend])
    f.event('roles',master=master,backup=backup,image=f.V7)
    proc(stack,['ip','netns','exec',f.CLIENT,'tcpdump','-U','-i','eth0','-s','96','-w',out/'client.pcap','arp or tcp port 18081'],'tcpdump.log')
    proc(stack,['ip','netns','exec',f.BENS[0],'tcpdump','-U','-i','eth0','-s','112','-w',out/'backend.pcap','arp or tcp port 18080'],'backend-capture.log')
    for owner in f.IDS:
        for label, cmd, dev in (('service', ['nsenter','-t', str(f.IDS[owner][1]),'-n'], 'eth1'),
                                ('wire', ['ip','netns','exec',f.SW], f.PORT[owner][0])):
            proc(stack,cmd + ['tcpdump','-p','-U','--immediate-mode','-i',dev,'-nn','-s','160','-w',out/(owner+'-'+label+'.pcap'),
                 'arp or (tcp and (port 54171 or port 18081 or port 18080))'],owner+'-'+label+'.log')
    def sample(owner,label):
        data = {}
        for table in ('ct_map','fc_v4_map','nat_map'):
            rows = f.rows(owner,table)
            if table != 'nat_map':
                rows = [r for r in rows if socket.htons(54171) in (r['key']['sport'],r['key']['dport'])]
            data[table] = rows
        data['neigh']=f.enter(owner,'ip','neigh','show')
        data['epoch']=time.time()
        snapshot(owner+'-'+label+'.json',data)
    # Warm up ARP before starting the once-only long connection.
    wait(lambda: subprocess.run(['ip','netns','exec',f.CLIENT,'python3',str(here/'fabric/client.py'),'6',vip,'18081'],capture_output=True).returncode==0,20)
    proc(stack,['ip','netns','exec',f.CLIENT,'python3','-u',here/'tcp-probe.py',vip,client],'probe.jsonl')
    wait(lambda: all(any(r['kind']==k for r in probes()) for k in ('held','new')),10)
    def held_entries(owner):
        return [r['key'] for r in f.rows(owner,'ct_map') if r['key']['l4proto']==6 and socket.htons(54171) in (r['key']['sport'],r['key']['dport'])]
    until=time.monotonic()+35
    while not held_entries(backup) and time.monotonic()<until: time.sleep(1)
    ct={x:held_entries(x) for x in f.IDS}
    snapshot('prefault-held-ct.json',ct)
    for owner in f.IDS:
        snapshot(owner+'-held-ct.json',[r for r in f.rows(owner,'ct_map') if r['key'] in ct[owner]])
    before=f.n(f.CLIENT,'ip','neigh','show',vip)
    for owner in f.IDS: sample(owner,'pre')
    snapshot('clock.json',dict(epoch=time.time(),mono=time.monotonic()))
    fault=time.monotonic()
    for dev in f.PORT[master]: f.n(f.SW,'ip','link','set',dev,'down')
    # Only observe the surviving node. LoxiLB elects and advertises the VIP itself.
    wait(lambda:state(backup)=='MASTER',15)
    promoted=time.monotonic()
    sample(backup,'promoted')
    wait(lambda: any(r['kind']=='new' and r['t']>promoted for r in probes()),18)
    sample(backup,'new-echo')
    time.sleep(3)
    sample(backup,'plus3')
    time.sleep(11)
    sample(backup,'end')
    rows=probes()
    result={'image':f.V7,'fault_monotonic':fault,'promoted_s':promoted-fault,'before_neigh':before,
            'after_neigh':f.n(f.CLIENT,'ip','neigh','show',vip),'standby_ct_keys':len(ct[backup]),'master_ct_keys':len(ct[master])}
    for kind in ('new','held'):
        left=[r for r in rows if r['kind']==kind and r['t']<fault]
        # A reply during link isolation can still belong to the former master.
        right=[r for r in rows if r['kind']==kind and r['t']>=promoted]
        result[kind]={'pre':left[-1], 'post':right[0] if right else None}
        if right:
            result[kind].update(gap_s=right[0]['t']-left[-1]['t'],fault_to_echo_s=right[0]['t']-fault)
    result['held_errors']=[r for r in rows if r['kind']=='held_error']
    result['observation_after_fault_s']=time.monotonic()-fault
    snapshot('result.json',result)
    f.event('native_tcp',**result)
