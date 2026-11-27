import asyncio
import importlib.util
import pathlib
import sys
import types
import unittest

for name in ("aiomoqt", "aiomoqt.client", "aiomoqt.track", "aiomoqt.types",
             "aiopquic", "aiopquic.quic", "aiopquic.quic.configuration"):
    sys.modules[name] = types.ModuleType(name)
sys.modules["aiomoqt.client"].MOQTClient = object
sys.modules["aiomoqt.track"].SubscribedTrack = object
sys.modules["aiomoqt.types"].MOQTRequestError = ValueError
sys.modules["aiopquic.quic.configuration"].QuicConfiguration = object
spec = importlib.util.spec_from_file_location(
    "broker", pathlib.Path(__file__).with_name("broker.py"))
broker_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker_mod)

TARGET="127.0.0.1:16968"
ARGS=types.SimpleNamespace(endpoint=[TARGET],budget=.15,generation="unit-test",evidence=None)


class EarlyVerdict(unittest.IsolatedAsyncioTestCase):
    async def query(self, broker):
        class Request:
            async def readline(self):
                return (TARGET + "\n").encode()

        class Response:
            payload=b""
            def write(self,data):
                self.payload+=data
            async def drain(self):
                pass
            def close(self):
                pass
            async def wait_closed(self):
                pass

        response=Response()
        await asyncio.wait_for(broker.handle(Request(),response),.65)
        return response.payload

    async def test_protocol_ready_while_teardown_is_still_running(self):
        class Peer(broker_mod.Broker):
            async def probe(self,address,details,verdict):
                verdict(True)
                await finish.wait()
        finish=asyncio.Event()
        broker=Peer(ARGS)
        try:
            self.assertEqual(await self.query(broker),b"1")
            self.assertIn(TARGET,broker.running)
            self.assertEqual(await self.query(broker),b"0")
        finally:
            finish.set()
            async with asyncio.timeout(.3):
                while TARGET in broker.running:
                    await asyncio.sleep(.01)

    async def test_no_protocol_verdict_before_deadline(self):
        class Peer(broker_mod.Broker):
            async def probe(self,address,details,verdict):
                await asyncio.Future()
        broker=Peer(ARGS)
        self.assertEqual(await self.query(broker),b"0")
        async with asyncio.timeout(.3):
            while TARGET in broker.running:
                await asyncio.sleep(.01)


if __name__=="__main__":
    unittest.main()
