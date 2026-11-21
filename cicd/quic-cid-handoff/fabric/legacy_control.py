"""Run ordinary traffic on its own VIP and LB throughout the CID event."""
import json
import time

def start(f, stack, spawn, out, image, here):
    owner = 'legacy7'
    tag = f.NAMES[owner] = f.TAG + '-legacy'
    spawn(stack, ['ip','netns','exec', f.BENS[0], 'python3', here/'echo.py','A'], out/'legacy-echo.log')
    f.run('docker','run','--pull','never','-d','--network','none','--privileged','--name',tag,
          '--entrypoint','/bin/sh',image,'-ec',
          'mount --make-rprivate /; until test -f /tmp/q7-ready; do sleep .1; done; exec /root/loxilb-io/loxilb/loxilb --egr-hooks --loglevel=info')
    stack.callback(f.run,'docker','rm','-f',tag)
    def receipt():
        import subprocess
        with (out/'legacy-lb.log').open('w') as log:
            subprocess.run(['docker','logs','--tail','180',tag], stdout=log, stderr=log)
            subprocess.run(['docker','inspect','-f','{{json .State}}',tag], stdout=log, stderr=log)
    stack.callback(receipt)
    f.IDS[owner] = f.docker_id(owner)
    for index, (bridge, prefix, dev) in enumerate([('front',f.FRONT,'eth1'),('back',f.BACK,'eth0')]):
        f.attach(10+index,owner,bridge,prefix+'41',dev,True,f.IDS[owner][1])
    f.enter(owner,'ip','addr','add',f.LEG+'/32','dev','eth1')
    f.run('docker','exec',tag,'touch','/tmp/q7-ready')
    for attempt in range(70):
        try:
            f.api(owner,'GET','/all')
            break
        except RuntimeError:
            if attempt == 69:
                raise
            time.sleep(.35)
    # The management API answers while asynchronous TC initialization is
    # still in progress. Expose traffic only after both ingress hooks exist.
    for _ in range(100):
        if all(any(row.get('kind') == 'bpf' for row in json.loads(
                f.enter(owner, 'tc', '-j', 'filter', 'show', 'dev', dev, 'ingress')))
               for dev in ('eth0', 'eth1')):
            break
        time.sleep(.2)
    else:
        raise RuntimeError('legacy ingress hooks did not become ready')
    for proto, (_, port) in f.PORTS.items():
        f.setup_rule(owner,f.LEG,proto,port,[f.A])
    f.route(f.LEG,owner)
    # Wait for the asynchronous routes and NAT workers before opening controls.
    for _ in range(80):
        if len(f.rows(owner, 'nat_map')) == len(f.PORTS):
            break
        time.sleep(.25)
    try:
        f.check('before','A')
    except RuntimeError:
        (out/'legacy-debug.json').write_text(json.dumps(dict(
            nat=f.rows(owner,'nat_map'), ct=f.rows(owner,'ct_map'),
            lb_routes=f.enter(owner,'ip','-4','route'), listeners=f.n(f.BENS[0],'ss','-lntup'),
            return_route=f.n(f.BENS[0],'ip','route','get',f.LEG),
            client_route=f.n(f.CLIENT,'ip','route','get',f.LEG), back=f.n(f.BENS[0],'ip','neigh'),
            lb=f.enter(owner,'ip','neigh'),log=f.run('docker','logs','--tail','40',tag))))
        raise
    log, ready, done = (out/i for i in ('stream.log','stream.ready','stream.done'))
    proc = spawn(stack,['ip','netns','exec',f.CLIENT,'python3',here/'stream-client.py',f.LEG,ready,done],log)
    for _ in range(50):
        if ready.exists():
            break
        time.sleep(.1)
    if not ready.exists():
        raise RuntimeError('legacy session setup failed')
    def finish():
        f.check('after','A')
        done.touch()
        if proc.wait(timeout=5):
            raise RuntimeError(log.read_text())
        f.event('legacy_continuity', image=image, **json.loads(log.read_text()))
    return finish
