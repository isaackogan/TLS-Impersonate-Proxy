# Pin one exact identity. /profiles lists every browser and OS TIP can be, each with the User-Agent it will send and a stable id.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-requests-profile.py
# Prints: the chosen profile's User-Agent twice: once from the catalogue, once as the destination saw it.
import requests

TIP = "http://localhost:8080"

catalogue = requests.get(f"{TIP}/profiles").json()
profile = next(p for p in catalogue["profiles"] if p["browser"] == "Chrome" and p["os"] == "Windows")
print(profile["userAgent"])
r = requests.get(
    "https://tls.browserleaks.com/json",
    proxies={"http": TIP, "https": TIP},
    verify="tip-ca.pem",
    headers={"X-Tip-Profile": profile["id"]},
)
print(r.json()["user_agent"])
