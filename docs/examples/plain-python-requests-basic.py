# Chrome fingerprint through TIP in plain mode: http:// to TIP, X-Tip-Scheme makes TIP speak TLS upstream.
# Run: python3 plain-python-requests-basic.py
# Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import requests

TIP = "http://localhost:8080"

r = requests.get(
    "http://tls.browserleaks.com/json",
    proxies={"http": TIP},
    headers={"X-Tip-Scheme": "https", "X-Tip-Browser": "Chrome", "X-Tip-Os": "Windows"},
)
body = r.json()
print(body["user_agent"])
print(body["ja4"], body["akamai_hash"])
