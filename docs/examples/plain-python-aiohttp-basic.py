# Chrome fingerprint through TIP with aiohttp in plain mode.
# Run: python3 plain-python-aiohttp-basic.py
# Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import asyncio

import aiohttp


async def main():
    async with aiohttp.ClientSession() as session:
        async with session.get(
            "http://tls.browserleaks.com/json",
            proxy="http://localhost:8080",
            headers={"X-Tip-Scheme": "https", "X-Tip-Browser": "Chrome", "X-Tip-Os": "Android"},
        ) as r:
            body = await r.json()
    print(body["user_agent"])
    print(body["ja4"], body["akamai_hash"])


asyncio.run(main())
