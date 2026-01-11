# Chrome fingerprint with explicit HTTP/2 SETTINGS, written as a cookie-style key-value list.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-requests-settings.py
# Prints: the HTTP/2 fingerprint the destination derived from those SETTINGS.
import requests

TIP = "http://localhost:8080"

r = requests.get(
    "https://tls.browserleaks.com/json",
    proxies={"http": TIP, "https": TIP},
    verify="tip-ca.pem",
    headers={
        "X-Tip-Browser": "Chrome",
        "X-Tip-Http2Settings": "HeaderTableSize=65536; EnablePush=0; InitialWindowSize=6291456; MaxHeaderListSize=262144; ConnectionFlow=15663105",
    },
)
print(r.json()["akamai_hash"])
