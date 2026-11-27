"""PoC client supervisor. Retry a failed tunnel against the same VIP, without operator input."""
import argparse
import subprocess
import time

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--ip',required=True)
    parser.add_argument('--port',type=int,required=True)
    parser.add_argument('client',nargs=argparse.REMAINDER)
    cfg=parser.parse_args()
    for attempt in range(40):
        print(f'epoch={time.time():.6f} event=attempt attempt={attempt+1}',flush=True)
        port=cfg.port+attempt
        result=subprocess.run([*cfg.client,'-bind',f'{cfg.ip}:{port}','-mode','watch'])
        if result.returncode==0:
            return
        print(f'epoch={time.time():.6f} event=retry reason_exit={result.returncode}',flush=True)
        time.sleep(.25)
    raise SystemExit('reconnect attempts exhausted')

if __name__=='__main__': main()
