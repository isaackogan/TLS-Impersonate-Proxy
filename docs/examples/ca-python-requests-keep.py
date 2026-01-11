# Chrome TLS and HTTP/2 fingerprint while keeping your own Accept and User-Agent, via X-Tip-Keep.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-requests-keep.py
# Prints: your User-Agent unchanged, then Chrome's JA4 and HTTP/2 fingerprint.
import requests

TIP = "http://localhost:8080"

r = requests.get(
    "https://tls.browserleaks.com/json",
    proxies={"http": TIP, "https": TIP},
    verify="tip-ca.pem",
    headers={
        "X-Tip-Browser": "Chrome",
        "X-Tip-Keep": "Accept, User-Agent",
        "Accept": "application/json",
        "User-Agent": "scout/1.0",
    },
)
body = r.json()
print(body["user_agent"])
print(body["ja4"], body["akamai_hash"])
