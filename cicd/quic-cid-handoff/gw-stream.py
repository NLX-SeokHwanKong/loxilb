"""Independent TCP sockets; each tries connect once and reports every matching echo."""
import json
import socket
import sys
import threading
import time

lock = threading.Lock()


def emit(**fields):
    with lock:
        print(json.dumps(dict(epoch=time.time(), **fields)), flush=True)


def stream(vip, sport, address):
    try:
        with socket.socket() as sock:
            sock.settimeout(12)
            sock.bind((address, sport))
            sock.connect((vip, 18081))
            for i in range(10000):
                text = f"{sport}.{i}".encode()
                sock.sendall(text)
                expect = b"A/" + text
                data = b""
                while len(data) < len(expect):
                    chunk = sock.recv(len(expect) - len(data))
                    if not chunk:
                        raise EOFError("server EOF")
                    data += chunk
                assert data == expect
                emit(vip=vip, sport=sport, i=i)
                time.sleep(0.12)
    except Exception as exc:
        emit(vip=vip, sport=sport, error=repr(exc))


threads = []
for idx, vip in enumerate(sys.argv[1:]):
    for flow in range(3):
        t = threading.Thread(
            target=stream,
            args=(vip, 54170 + idx * 3 + flow, "198.18.241." + str(flow + 1)),
        )
        t.start()
        threads.append(t)
for t in threads:
    t.join()
