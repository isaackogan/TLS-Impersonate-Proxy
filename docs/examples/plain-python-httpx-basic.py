# Firefox fingerprint through TIP with httpx in plain mode.
# Run: python3 plain-python-httpx-basic.py
# Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import httpx

with httpx.Client(proxy="http://localhost:8080") as client:
    r = client.get(
        "http://tls.browserleaks.com/json",
        headers={"X-Tip-Scheme": "https", "X-Tip-Browser": "Firefox", "X-Tip-Os": "MacOS"},
    )
body = r.json()
print(body["user_agent"])
print(body["ja4"], body["akamai_hash"])
