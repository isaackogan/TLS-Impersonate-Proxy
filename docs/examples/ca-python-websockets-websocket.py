# A WebSocket through TIP's MITM tunnel with the websockets library in CA mode.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-websockets-websocket.py
# Prints: the echoed message.
import asyncio
import ssl

from python_socks.async_.asyncio import Proxy
from websockets.asyncio.client import connect


async def main():
    ctx = ssl.create_default_context(cafile="tip-ca.pem")
    proxy = Proxy.from_url("http://localhost:8080")
    sock = await proxy.connect(dest_host="echo.websocket.org", dest_port=443)
    async with connect(
        "wss://echo.websocket.org",
        sock=sock,
        ssl=ctx,
        server_hostname="echo.websocket.org",
        additional_headers={"X-Tip-Browser": "Chrome"},
    ) as ws:
        await ws.send("hello through tip")
        print(await ws.recv())


asyncio.run(main())
