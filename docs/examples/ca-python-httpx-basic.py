# Firefox fingerprint through TIP with httpx in CA mode.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-httpx-basic.py
# Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import httpx

with httpx.Client(proxy="http://localhost:8080", verify="tip-ca.pem") as client:
    r = client.get(
        "https://tls.browserleaks.com/json",
        headers={"X-Tip-Browser": "Firefox", "X-Tip-Os": "MacOS"},
    )
body = r.json()
print(body["user_agent"])
print(body["ja4"], body["akamai_hash"])
