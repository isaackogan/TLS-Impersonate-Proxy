# Chrome fingerprint through TIP in CA mode: the client trusts TIP's CA so https:// works unchanged.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-requests-basic.py
# Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import requests

TIP = "http://localhost:8080"

r = requests.get(
    "https://tls.browserleaks.com/json",
    proxies={"http": TIP, "https": TIP},
    verify="tip-ca.pem",
    headers={"X-Tip-Browser": "Chrome", "X-Tip-Os": "Windows"},
)
body = r.json()
print(body["user_agent"])
print(body["ja4"], body["akamai_hash"])
