"""Repeat the full CONNECT-IP client exercise on failure, using a fresh UDP port."""
import subprocess
import sys
import time

if __name__ == '__main__':
    source, *client = sys.argv[1:]
    deadline = time.monotonic() + 110
    for i in range(440):
        if time.monotonic() >= deadline:
            raise SystemExit("CONNECT-IP recovery timeout")
        print(f'epoch={time.time():.6f} event=attempt attempt={i+1}', flush=True)
        if subprocess.run([*client, '-bind', f'{source}:{55200+i}']).returncode == 0:
            break
        time.sleep(.25)
    else:
        raise SystemExit('CONNECT-IP recovery exhausted')
