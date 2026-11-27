"""Check native QUIC and MoQ against the backend address from the LB network."""

import argparse
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import ssl
import time

from aiomoqt.client import MOQTClient
from aiomoqt.track import SubscribedTrack
from aiomoqt.types import MOQTRequestError
from aiopquic.quic.configuration import QuicConfiguration

DRAFT = 16
TRACK_DOES_NOT_EXIST = 0x10


class Broker:
    def __init__(self, args):
        self.args = args
        self.running = {}
        self.sequence = 0
        self.targets = {}
        for endpoint in args.endpoint:
            address, _, port = endpoint.partition(":")
            host = str(ipaddress.IPv4Address(address))
            port = int(port or "16968")
            if not 0 < port < 65536:
                raise ValueError(f"invalid target port: {port}")
            self.targets[f"{host}:{port}"] = (host, port)

    def stamp(self, event, **fields):
        row = json.dumps({"event": event, "time_ns": time.time_ns(), "generation": self.args.generation, **fields})
        print(row, flush=True)
        if self.args.evidence:
            with open(self.args.evidence, "a") as stream:
                print(row, file=stream)

    async def probe(self, address, details, verdict):
        cfg = QuicConfiguration(is_client=True, server_name=self.args.server_name, verify_mode=ssl.CERT_REQUIRED)
        if self.args.mode == "mtls":
            credential = Path(self.args.credential).resolve(strict=True)
            cfg.load_cert_chain(str(credential / "client.pem"), str(credential / "client.key"))
            details["credential_version"] = credential.name
        host, port = address
        client = MOQTClient(host, port, path="/moq-relay", use_quic=True, verify_tls=True,
                            ca_file=self.args.server_ca, configuration=cfg, supported_drafts=[DRAFT])
        async with client.connect() as session:
            details["quic"] = True
            details["quic_ready_ns"] = time.time_ns()
            await session.client_session_init(timeout=self.args.budget)
            details["draft"] = session.negotiated_draft
            details["moq_setup_ns"] = time.time_ns()
            if session.negotiated_draft != DRAFT:
                verdict(False)
                return
            track = SubscribedTrack(session, self.args.namespace, self.args.track, on_object=lambda *a, **k: None)
            try:
                await track.subscribe(timeout=self.args.budget)
                details["moq_response"] = "subscribe_ok"
                details["moq_response_ns"] = time.time_ns()
                verdict(True)
            except MOQTRequestError as err:
                details["moq_response"] = int(err.error_code)
                details["moq_response_ns"] = time.time_ns()
                # The relay traversed the authenticated subscription path and replied
                # correctly when no publisher had announced the selected track.
                verdict(int(err.error_code) == TRACK_DOES_NOT_EXIST)

    async def complete_probe(self, target, address, details, sequence, result):
        def verdict(ok):
            if not result.done():
                self.stamp("result", target=target, sequence=sequence, ok=ok, **details)
                result.set_result(ok)

        try:
            # Report readiness once the service responds. Keep the socket slot
            # occupied until transport cleanup so requests cannot overlap.
            await self.probe(address, details, verdict)
        except asyncio.CancelledError:
            if not result.done():
                details["failure"] = "TimeoutError"
            raise
        except Exception as err:
            if not result.done():
                details["failure"] = type(err).__name__
        finally:
            verdict(False)

    async def handle(self, reader, writer):
        ok = False
        probe = None
        result = None
        try:
            async with asyncio.timeout(.05):
                line = await reader.readline()
            target = line.decode("ascii").strip()
            address = self.targets.get(target)
            if address is None or target in self.running:
                return
            self.sequence += 1
            sequence = self.sequence
            details = {}
            result = asyncio.get_running_loop().create_future()
            probe = asyncio.create_task(self.complete_probe(target, address, details, sequence, result))
            self.running[target] = probe
            probe.add_done_callback(lambda _task: self.running.pop(target, None))
            self.stamp("start", target=target, sequence=sequence, concurrent=len(self.running))
            async with asyncio.timeout(self.args.budget):
                ok = await asyncio.shield(result)
        except (UnicodeError, ValueError, TimeoutError):
            if probe is not None and not probe.done():
                probe.cancel()
                if not result.done():
                    details["failure"] = "TimeoutError"
                    self.stamp("result", target=target, sequence=sequence, ok=False, **details)
                    result.set_result(False)
        finally:
            writer.write(b"1" if ok else b"0")
            try:
                await writer.drain()
            except (BrokenPipeError, ConnectionError):
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionError):
                pass


async def main(args):
    os.umask(0o077)
    os.environ.pop("SSLKEYLOGFILE", None)
    broker = Broker(args)
    async with await asyncio.start_unix_server(broker.handle, path=args.socket, limit=128) as server:
        Path(args.socket).chmod(0o600)
        await server.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("tls", "mtls"))
    ap.add_argument("--socket", required=True)
    ap.add_argument("--budget", type=float, required=True)
    ap.add_argument("--endpoint", required=True, action="append")
    ap.add_argument("--evidence")
    ap.add_argument("--generation", default="primary")
    ap.add_argument("--server-name", required=True)
    ap.add_argument("--server-ca", required=True)
    ap.add_argument("--credential", help="Directory containing client.pem and client.key")
    ap.add_argument("--namespace", required=True)
    ap.add_argument("--track", default="ready")
    args = ap.parse_args()
    if args.mode == "mtls" and not args.credential:
        ap.error("--credential is required in mtls mode")
    asyncio.run(main(args))
