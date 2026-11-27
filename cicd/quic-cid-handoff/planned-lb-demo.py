"""Exercise one running client across a planned, drained B handoff on a dedicated fabric."""
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
from contextlib import ExitStack

HERE=Path(__file__).resolve().parent
stage=Path(os.environ['QMZ_STAGE']).resolve()
base=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(base))
spec=importlib.util.spec_from_file_location('fabric',base/'fabric-trial.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)

def wait_for(fn,seconds):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if fn():return
        time.sleep(.2)
    raise RuntimeError(f'condition pending after {seconds}s')

def spawn(stack,args,path):
    log=stack.enter_context(path.open('w'))
    proc=subprocess.Popen(list(map(str,args)),stdout=log,stderr=log,start_new_session=True)
    def stop():
        if proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM)
        proc.wait(timeout=6)
    stack.callback(stop)
    return proc

def rule(owner,backends):
    f.api(owner,'POST',body={'serviceArguments':dict(externalIP=f.CID,port=18443,protocol='udp',mode=2,
          sel=7,managed=True,inactiveTimeout=6,quicLb={'sidLen':4},name='mvp'),
          'endpoints':[dict(endpointIP=e,targetPort=18444,weight=1) for e in backends]})

def main():
    selective = os.environ.get('QMZ_DRAIN') == 'selective'
    from selective_handoff import adapter
    fabric = adapter(f) if selective else f.Fabric()
    ip_tunnel_mode = os.environ.get('QMZ_TUNNEL') == 'ip'
    cert = Path(os.environ.get('QMZ_CERT', stage/'cert')).resolve()
    binary=stage/'bin/mvp-client'
    out=Path(sys.argv[2]);out.mkdir()
    with ExitStack() as stack:
        if selective:
            stack.callback(fabric.release)
        for ns in [f.SW,f.CLIENT,*f.BENS]:
            f.run('ip','netns','add',ns)
            stack.callback(f.run,'ip','netns','delete',ns)
            f.n(ns,'ip','link','set','lo','up')
        for bridge in ('front','back'):
            f.n(f.SW,'ip','link','add',bridge,'type','bridge')
            f.n(f.SW,'ip','link','set',bridge,'up')
        f.attach(1,f.CLIENT,'front',f.FRONT+'1','eth0',True)
        for i,ns in enumerate(f.BENS):
            f.attach(i+2,ns,'back',[f.A,f.B][i],'eth0',True)
        if ip_tunnel_mode:
            import ip_tunnel
            ip_tunnel.gateway(f, stack, spawn, stage, out, cert)
        else:
            for cmd in (['echo','-listen','127.0.0.1:16445'],
                        ['gateway','-listen',f.A+':18444','-name','A','-sid',f.A,'-authority','masque-poc.test:16444',
                         '-target','127.0.0.1:16445','-cert',cert/'A.pem','-key',cert/'A.key']):
                spawn(stack,['ip','netns','exec',f.BENS[0],binary,*cmd],out/(cmd[0]+'.log'))
        legacy = os.environ.get('QMZ_LEGACY_IMAGE')
        if legacy:
            from legacy_control import start as start_legacy
            finish_legacy = start_legacy(f, stack, spawn, out, legacy, base)
        for i,owner in enumerate(('old','new')):
            tag=f.NAMES[owner]=f.TAG+'-'+owner
            f.run('docker','run','--pull','never','-d','--network','none','--privileged','--name',tag,
                  '--entrypoint','/bin/sh',f.V7,'-ec',
                  'mount --make-rprivate /; until test -f /tmp/q7-ready; do sleep .1; done; exec /root/loxilb-io/loxilb/loxilb --egr-hooks' + (f' --cid-handoff={f.CID}@eth1,eth0' if selective else ''))
            stack.callback(f.run,'docker','rm','-f',tag)
            f.IDS[owner]=f.docker_id(owner)
            f.PORT[owner]=[f.attach(4+2*i+j,owner,br,prefix+str(f.IND[owner]),dev,owner=='old',f.IDS[owner][1])
                           for j,(br,prefix,dev) in enumerate([('front',f.FRONT,'eth1'),('back',f.BACK,'eth0')])]
            f.enter(owner,'ip','addr','add',f.CID+'/32','dev','eth1')
            f.run('docker','exec',tag,'touch','/tmp/q7-ready')
            for attempt in range(55):
                try:f.api(owner,'GET','/all');break
                except RuntimeError:
                    if attempt==54:raise
                    time.sleep(.4)
        f.route(f.CID,'old')
        rule('old',[f.A,f.B])
        wait_for(lambda:len(fabric.read('old').guard)==2,20)
        rule('old',[f.A]);rule('new',[f.A])
        key=(f.u32(f.CID),f.u32(f.B),socket.htons(18444),1)
        wait_for(lambda:fabric.read('old').guard.get(key)==0 and len(fabric.read('new').guard)==1,25)
        detector = os.environ.get('QMZ_DETECTOR')
        monitor = None
        if detector:
            if detector not in ('bgp', 'bfd'):
                raise ValueError(detector)
            from bfd.observe import Monitor
            monitor = Monitor(f, stack, spawn, out, stage, detector)
            capture_log = out/'candidate-egress.log'
            spawn(stack, ['nsenter','-t',str(f.IDS['new'][1]),'-n','tcpdump','--immediate-mode','-nn','-l','-tt','-i','eth0',
                          'udp','and','dst','host',f.A,'and','dst','port','18444'],capture_log)
            wait_for(lambda:'listening on' in capture_log.read_text(),4)
            rule_json = f.api('old','GET','/all')
            (out/'rule.json').write_text(json.dumps(rule_json))
        clientlog=out/'client.log'
        if ip_tunnel_mode:
            watch = ip_tunnel.client(f, stack, spawn, HERE, stage, clientlog, cert)
            wait_for(lambda:'event=tcp_echo' in clientlog.read_text(),30)
        else:
            watch=spawn(stack,['ip','netns','exec',f.CLIENT,'python3','-u',HERE/'reconnect-client.py',
                        '--ip',f.FRONT+'1','--port','55200',binary,'client','-target','127.0.0.1:16445',
                        '-ca',cert/'ca.pem','-authority','masque-poc.test:16444','-server-name','masque-poc.test',
                        '-remote',f.CID+':18443','-run','planned-lb'],clientlog)
            wait_for(lambda:'event=received' in clientlog.read_text(),30)
        if monitor:
            monitor.wait_ready()
            assert not fabric.drained('old')
            (out/'ct-before.json').write_text(json.dumps(f.rows('old','ct_map')))
        scope_checks = os.environ.get('QMZ_VERIFY_SCOPE') == '1'
        if scope_checks:
            if not selective or not monitor:
                raise ValueError('scope checks require the selective mode and a live detector')
            import scope_check
            scope_check.before(f, fabric)
        fault_epoch = time.time()
        start=time.monotonic()
        # Quiesce ingress in both directions on this VIP's dedicated switch ports.
        # Donor, its pinned maps and the fabric ownership record remain live.
        for idx, dev in enumerate(f.PORT['old']):
            f.n(f.SW,'ip','link','set',dev,'down')
            if scope_checks and idx == 0:
                scope_check.before(f, fabric)
        if scope_checks:
            witnesses = scope_check.fenced(f, fabric)
        if monitor:
            monitor.wait_alarm()
            alarm = time.monotonic()
        if monitor:
            monitor.save_bfd('alarm')
        gc_requests = 0
        if monitor and os.environ.get('QMZ_DRAIN') == 'age':
            # Exclusive donor in the test only. The read schedules the native age
            # scan; expiry conditions and final admission checks still apply.
            assert f.NAMES['old'].startswith(f.TAG+'-') and f.NAMES['old'].endswith('-old')
            fabric.read('old').validate()
            until = start + 45
            while not fabric.drained('old') and time.monotonic() < until:
                f.enter('old','curl','-fsS','--max-time','3','-o','/dev/null',
                        'http://127.0.0.1:11111/netlox/v1/config/conntrack/all')
                gc_requests += 1
                time.sleep(1)
        if selective:
            fabric.prepare('old','new')
            if scope_checks:
                scope_check.after(f, fabric, witnesses)
        wait_for(lambda:fabric.drained('old'),145)
        drained=time.monotonic()
        donor=f.transfer(fabric,'old','new')
        assert fabric.read('new').guard==donor.guard and not fabric.is_open('old') and fabric.is_open('new')
        admitted = time.monotonic()
        f.event('publication', fault_epoch=fault_epoch, admitted_s=round(admitted-start,4))
        f.run('docker','stop','-t','1',f.NAMES['old'])
        def resumed():
            s=clientlog.read_text()
            replies=list(re.finditer(r'event=connect_response .*?gateway=A conn=(\S+)',s))
            return len(replies)>1 and replies[0][1]!=replies[-1][1] and 'event=received' in s[replies[-1].end():]
        if ip_tunnel_mode:
            if watch.wait(timeout=120) or 'event=trial_complete' not in clientlog.read_text():
                raise RuntimeError('CONNECT-IP application or policy failure')
            lines = clientlog.read_text().splitlines()
            echo_line = next(line for line in lines if 'event=tcp_echo' in line and
                             datetime.strptime(line[:26], '%Y/%m/%d %H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp() > fault_epoch)
            f.event('connect_ip_result', attempts=sum('event=attempt ' in line for line in lines),
                    assigned=sum('event=vpn_config' in line for line in lines),
                    policy_verified=any('event=tcp_blocked' in line and 'phase=post' in line for line in lines))
        else:
            wait_for(resumed,60)
            assert watch.poll() is None
            replies = list(re.finditer(r'event=connect_response .*?gateway=A conn=(\S+)', clientlog.read_text()))
            echo_line = next(line for line in clientlog.read_text()[replies[-1].end():].splitlines() if 'event=received' in line)
        echo_epoch = datetime.strptime(echo_line[:26], '%Y/%m/%d %H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
        if monitor:
            wait_for(lambda: re.search(r'^\d+\.\d+ IP ', capture_log.read_text(), re.M), 4)
            packet_times = [float(x[1]) for line in capture_log.read_text().splitlines()
                            if (x := re.match(r'^(\d+\.\d+) IP ', line))]
            assert packet_times and min(packet_times) >= fault_epoch
            f.event('detector_trial', first_forward_s=round(min(packet_times)-fault_epoch,4),
                    app_echo_s=round(echo_epoch-fault_epoch,4), age_requests=gc_requests, detector=detector, fault_epoch=fault_epoch,
                    alarm_s=round(alarm-start,4), drained_s=round(drained-start,4),
                    admitted_s=round(admitted-start,4), rules_image=f.V7, hold_s=9, keepalive_s=3,
                    bfd_interval_ms=200 if detector=='bfd' else None)
        f.event('planned_lb_recovery',image=f.V7,drain_seconds=round(drained-start,3),observed_seconds=round(time.monotonic()-start,3),
                removed_history=fabric.read('new').guard[key],client_pid=watch.pid,
                attempts=clientlog.read_text().count('event=attempt '),donor_stopped=True)
        if legacy:
            finish_legacy()
    f.event('passed',cleanup=True)
if __name__=='__main__': main()
