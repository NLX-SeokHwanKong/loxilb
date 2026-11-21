import socket,sys,time
proto=int(sys.argv[1]); dst=sys.argv[2]; port=int(sys.argv[3])
payload=("qa-"+str(time.time_ns())).encode()
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if proto==17 else socket.SOCK_STREAM,proto) as s:
    s.settimeout(2)
    s.connect((dst,port));s.sendall(payload)
    response=s.recv(2048)
    site,echo=response.split(b"/",1)
    assert echo==payload and site in (b"A",b"B")
    print(site.decode())
