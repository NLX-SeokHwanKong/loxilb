import socket
import sys
import threading

site = sys.argv[1].encode() + b'/'

def stream(conn):
    with conn:
        conn.settimeout(10)
        try:
            while data := conn.recv(2048):
                conn.sendall(site + data)
        except OSError:
            return

def serve(protocol):
    kind = socket.SOCK_DGRAM if protocol == 17 else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind, protocol) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 18080))
        if kind == socket.SOCK_STREAM:
            sock.listen(16)
        while True:
            if kind == socket.SOCK_DGRAM:
                data, addr = sock.recvfrom(2048)
                sock.sendto(site + data, addr)
            else:
                conn, _ = sock.accept()
                threading.Thread(target=stream, args=(conn,), daemon=True).start()

threads = [threading.Thread(target=serve, args=(proto,)) for proto in (6,17,132)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
