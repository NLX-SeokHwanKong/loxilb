"""Keep the same three sockets open while the separate CID VIP changes owner."""
import json
import socket
import sys
import time
from contextlib import ExitStack
from pathlib import Path

with ExitStack() as opened:
    sockets = {}
    for proto, port in ((6,18081),(17,18082),(132,18083)):
        kind = socket.SOCK_DGRAM if proto==17 else socket.SOCK_STREAM
        sock=opened.enter_context(socket.socket(socket.AF_INET,kind,proto))
        sock.settimeout(2)
        sock.connect((sys.argv[1],port))
        sockets[proto]=sock
    rounds=0
    while True:
        for proto,sock in sockets.items():
            data = f'{proto}-{rounds}'.encode()
            sock.sendall(data)
            expected=b'A/'+data
            response=sock.recv(2048)
            while proto==6 and response and len(response)<len(expected):
                part=sock.recv(2048)
                if not part:break
                response+=part
            if response!=expected:
                raise RuntimeError((proto,rounds,response))
        rounds+=1
        if rounds==1:
            Path(sys.argv[2]).touch(exist_ok=False)
        if Path(sys.argv[3]).exists():
            print(json.dumps({'rounds_per_protocol':rounds,'reconnections':0}),flush=True)
            break
        time.sleep(.2)
