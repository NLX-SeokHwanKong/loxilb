"""TCP echo latency across a lab failover. The held socket is opened exactly once."""
import json
import socket
import sys
import threading
import time

vip, client = sys.argv[1:3]

log_lock = threading.Lock()

def event(kind, **values):
    with log_lock:
        print(json.dumps(dict(kind=kind, t=time.monotonic(), **values)), flush=True)

def probe(held):
    seq = 0
    sock = None
    while True:
        try:
            if sock is None:
                sock = socket.socket()
                sock.settimeout(12 if held else .30)
                if held:
                    sock.bind((client, 54171))
                sock.connect((vip, 18081))
            payload = ('h' if held else 'n') + str(seq)
            sock.sendall(payload.encode())
            expected = b'A/' + payload.encode()
            reply = b''
            while len(reply) < len(expected):
                data = sock.recv(len(expected)-len(reply))
                if not data:
                    raise EOFError()
                reply += data
            if reply != expected:
                raise ValueError(reply)
            event('held' if held else 'new', seq=seq, port=sock.getsockname()[1])
            seq += 1
        except (OSError, ValueError, EOFError) as e:
            event('held_error' if held else 'new_error', error=repr(e))
            if held:
                return
        finally:
            if not held and sock:
                sock.close()
                sock = None
        time.sleep(.12)

threading.Thread(target=probe,args=(True,),daemon=True).start()
probe(False)
