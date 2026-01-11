# What a rejected directive looks like: 418, empty body, one X-Tip-Error header per issue.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-requests-errors.py
# Prints: 418, then each X-Tip-Error line.
import requests

TIP = "http://localhost:8080"

r = requests.get(
    "https://tls.browserleaks.com/json",
    proxies={"http": TIP, "https": TIP},
    verify="tip-ca.pem",
    headers={"X-Tip-Browser": "Safari", "X-Tip-Timeout": "soon"},
)
print(r.status_code)
for issue in r.raw.headers.getlist("X-Tip-Error"):
    print(issue)
