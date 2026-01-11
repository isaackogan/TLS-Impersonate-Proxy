# Firefox on a randomly chosen mobile OS. One session keeps one connection, and one connection keeps one OS.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-requests-random.py
# Prints: three user agents; the OS is chosen once per connection, so they match within a session.
import requests

TIP = "http://localhost:8080"

with requests.Session() as session:
    session.proxies = {"http": TIP, "https": TIP}
    session.verify = "tip-ca.pem"
    session.headers.update({"X-Tip-Browser": "Firefox", "X-Tip-Os": "IOS,Android"})
    for _ in range(3):
        print(session.get("https://tls.browserleaks.com/json").json()["user_agent"])
