# Chrome fingerprint through TIP with aiohttp in CA mode.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-aiohttp-basic.py
# Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import asyncio
import ssl

import aiohttp


async def main():
    ctx = ssl.create_default_context(cafile="tip-ca.pem")
    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://tls.browserleaks.com/json",
            proxy="http://localhost:8080",
            ssl=ctx,
            headers={"X-Tip-Browser": "Chrome", "X-Tip-Os": "Android"},
        ) as r:
            body = await r.json()
    print(body["user_agent"])
    print(body["ja4"], body["akamai_hash"])


asyncio.run(main())
