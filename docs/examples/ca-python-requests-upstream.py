# Chrome fingerprint through TIP, then out through an upstream SOCKS5 proxy named by X-Tip-Proxy.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-requests-upstream.py
# Prints: the egress IP the destination saw, then the user agent and fingerprints.
import requests

TIP = "http://localhost:8080"

r = requests.get(
    "https://tls.browserleaks.com/json",
    proxies={"http": TIP, "https": TIP},
    verify="tip-ca.pem",
    headers={
        "X-Tip-Browser": "Chrome",
        "X-Tip-Proxy": "socks5://user:pass@residential.example:1080",
    },
)
body = r.json()
print(body["ip"])
print(body["user_agent"])
print(body["ja4"], body["akamai_hash"])
