"""Isolated, single-coordinator validation. Root only on the approved testbed."""
import json
import os
import socket
import struct
import subprocess
import sys
import time
from native_view import drained, native_view, u32
from contextlib import contextmanager, ExitStack
from pathlib import Path

from handoff import Hold, View, transfer

HERE = Path(__file__).resolve().parent
TAG = 'q7' + str(os.getpid())
V7 = os.environ['QMZ_TEST_IMAGE']
CID, LEG = '198.18.244.10', '198.18.244.11'
A, B = '198.18.243.20', '198.18.243.21'
PORTS = {'tcp': (6,18081),'udp': (17,18082),'sctp': (132,18083)}
IDS = {}
PORT = {}
CLOSED = {}
NAMES = {}
FRONT, BACK = '198.18.242.', '198.18.243.'
def run(*args, **kw):
    p = subprocess.run(list(map(str,args)),text=True,capture_output=True,timeout=45,**kw)
    if p.returncode:
        raise RuntimeError((args,p.returncode,(p.stderr or p.stdout)[-600:]))
    return p.stdout.strip()

def event(label, **data):
    print(json.dumps(dict(event=label,**data)),flush=True)

def n(name,*cmd):
    return run('ip','netns','exec',name,*cmd)

def enter(lb,*cmd):
    return run('nsenter','-t',IDS[lb][1],'-n',*cmd)

def docker_id(lb):
    r=json.loads(run('docker','inspect',NAMES[lb]))[0]
    if not r['State']['Running']:
        raise Hold('owner process unavailable')
    return r['Id'],r['State']['Pid'],r['State']['StartedAt']

def api(lb, method, path='', body=None):
    cmd=['curl','-fsS','--max-time','20','-X',method]
    if body is not None:
        cmd.extend(['-H','Content-Type: application/json','-d',json.dumps(body)])
    r=json.loads(enter(lb,*cmd,'http://127.0.0.1:11111/netlox/v1/config/loadbalancer'+path))
    if method!='GET' and r.get('result')!='Success':
        raise RuntimeError(r)
    return r

def setup_rule(lb,vip,proto,port,backends,cid=False):
    args=dict(externalIP=vip,port=port,protocol=proto,mode=2,sel=7 if cid else 0)
    if cid:
        args.update(managed=True,name='q7-cid',quicLb={'sidLen':4})
    api(lb,'POST',body=dict(serviceArguments=args,endpoints=[
        dict(endpointIP=e,targetPort=18444 if cid else 18080,weight=1) for e in backends]))

def map_pin(lb,name):
    return '/proc/{}/root/opt/loxilb/dp/bpf/{}'.format(IDS[lb][1],name)

def rows(lb,name):
    return [r['formatted'] for r in json.loads(run('bpftool','-j','map','dump','pinned',map_pin(lb,name)))]

class Fabric:
    """Only the test process writes rules or has the gate handle on this fabric."""
    def identity(self, lb):
        identity = docker_id(lb)
        if identity != IDS[lb]:
            raise Hold('incarnation changed')
        return identity

    def read(self,lb):
        ident=self.identity(lb)
        return native_view(ident,CID,rows(lb,'nat_map'),rows(lb,'cid_reply_guard'))

    def drained(self,lb):
        return drained(CID,rows(lb,'ct_map'))

    def restore(self,lb,k,v):
        if self.is_open(lb):
            raise Hold('candidate port exposed')
        key=struct.pack('=IIHH',*k); value=struct.pack('=I',v)
        run('bpftool','map','update','pinned',map_pin(lb,'cid_reply_guard'),
            'key','hex',*['%02x'%b for b in key],'value','hex',*['%02x'%b for b in value])

    def is_open(self,lb):
        fabric_ports={r['ifname']:r for r in json.loads(n(SW,'ip','-j','link','show'))}
        # Destroying a container netns also destroys the two switch-side veths.
        states=[bool(fabric_ports.get(dev,{}).get('master')) for dev in PORT[lb]]
        if len(set(states))!=1:
            raise Hold('partial fabric fence')
        return states[0]

    def close(self,lb):
        for dev in PORT[lb]:
            n(SW,'ip','link','set',dev,'nomaster')

    def open(self,lb):
        if any(self.is_open(peer) for peer in ('old','new') if peer!=lb):
            raise Hold('another port owns CID')
        for dev,bridge in zip(PORT[lb],('front','back')):
            n(SW,'ip','link','set',dev,'master',bridge)
        route(CID,lb)

    @contextmanager
    def quiesce(self,*lbs):
        with ExitStack() as stack:
            for lb in lbs:
                self.identity(lb)
                run('docker','pause',NAMES[lb])
                stack.callback(run,'docker','unpause',NAMES[lb])
            yield

def route(vip,lb):
    n(CLIENT,'ip','route','replace',vip+'/32','via',FRONT+str(IND[lb]))
    for ns in BENS:
        n(ns,'ip','route','replace',vip+'/32','via',BACK+str(IND[lb]))

def result(ns,vip,proto,port):
    return n(ns,'python3',HERE/'client.py',proto,vip,port)

def check(lb,expected):
    got={}
    for proto,(num,port) in PORTS.items():
        for _ in range(6):
            try:
                got[proto]=result(CLIENT,LEG,num,port)
                if got[proto]==expected:break
            except RuntimeError as e: event('retry_echo',proto=proto,detail=str(e)[-220:])
            time.sleep(.3)
        if got.get(proto)!=expected:
            raise RuntimeError(('legacy echo',lb,proto,got))
    event('legacy_echo',lb=lb,backend=got)

def attach(index,into,bridge,addr,dev,connected,pid=None):
    x,y=TAG+'x'+str(index), TAG+'y'+str(index)
    n(SW,'ip','link','add',x,'type','veth','peer','name',y)
    n(SW,'ip','link','set',y,'netns',pid or into)
    target=(lambda *a:enter(into,*a)) if pid else (lambda *a:n(into,*a))
    target('ip','link','set',y,'name',dev)
    target('ip','addr','add',addr+'/24','dev',dev)
    target('ip','link','set',dev,'up')
    n(SW,'ip','link','set',x,'up')
    if connected:n(SW,'ip','link','set',x,'master',bridge)
    return x

SW,CLIENT=TAG+'sw',TAG+'client'
BENS=[TAG+'a',TAG+'b']
IND={'old':30,'new':31,'legacy0':40,'legacy7':41}
