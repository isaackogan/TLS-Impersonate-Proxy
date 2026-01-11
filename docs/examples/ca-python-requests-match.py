# Let TIP infer the browser from your User-Agent with X-Tip-Match, and keep that User-Agent on the wire.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-requests-match.py
# Prints: your Firefox User-Agent unchanged, with a Firefox TLS and HTTP/2 fingerprint underneath it.
import requests

TIP = "http://localhost:8080"

r = requests.get(
    "https://tls.browserleaks.com/json",
    proxies={"http": TIP, "https": TIP},
    verify="tip-ca.pem",
    headers={
        "X-Tip-Match": "true",
        "X-Tip-Keep": "User-Agent",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    },
)
body = r.json()
print(body["user_agent"])
print(body["ja4"], body["akamai_hash"])
