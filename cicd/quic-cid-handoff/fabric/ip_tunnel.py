"""Set up real CONNECT-IP with a fixed VPN address and allowed/denied inner TCP."""
def gateway(f, stack, spawn, stage, out, cert):
    gw, client = f.BENS[0], f.CLIENT
    for ns, dev, addr in ((gw, 'qvr-gw', '198.18.77.1/32'), (client, 'qvr-cl', '198.18.77.2/32')):
        f.n(ns, 'ip','tuntap','add','dev',dev,'mode','tun')
        f.n(ns, 'ip','addr','add',addr,'dev',dev)
        f.n(ns, 'ip','link','set',dev,'mtu','1200','up')
    f.n(client,'ip','route','add','198.18.76.0/24','dev','qvr-cl')
    f.n(gw,'ip','route','add','198.18.77.2/32','dev','qvr-gw')
    for addr in ('198.18.76.10/32','198.18.76.11/32'):
        f.n(gw,'ip','addr','add',addr,'dev','lo')
    revoked = out/'revoked'
    revoked.mkdir()
    spawn(stack,['ip','netns','exec',gw,stage/'bin/connect-ip','gateway','-listen',f.A+':18444',
                 '-name','A','-sid',f.A,'-authority','masque-poc.test:16444','-tun','qvr-gw',
                 '-ca',cert/'ca.pem','-cert',cert/'A.pem','-key',cert/'A.key','-revoked',revoked],out/'gateway.log')

def client(f, stack, spawn, here, stage, log, cert):
    return spawn(stack,['ip','netns','exec',f.CLIENT,'python3','-u',here/'ip-recovery.py', f.FRONT+'1',
                        stage/'bin/connect-ip','client','-tun','qvr-cl','-ca',cert/'ca.pem',
                        '-cert',cert/'allow.pem','-key',cert/'allow.key','-authority','masque-poc.test:16444',
                        '-server-name','masque-poc.test','-remote',f.CID+':18443','-run','qa-device','-mode','nat'],log)
