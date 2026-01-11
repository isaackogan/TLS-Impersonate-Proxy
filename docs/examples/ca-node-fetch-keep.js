// Chrome TLS and HTTP/2 fingerprint while keeping your own Accept and User-Agent, via X-Tip-Keep.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && NODE_EXTRA_CA_CERTS=tip-ca.pem node ca-node-fetch-keep.js
// Prints: your User-Agent unchanged, then Chrome's JA4 and HTTP/2 fingerprint.
import { ProxyAgent } from "undici";

const r = await fetch("https://tls.browserleaks.com/json", {
  dispatcher: new ProxyAgent("http://localhost:8080"),
  headers: {
    "X-Tip-Browser": "Chrome",
    "X-Tip-Keep": "Accept, User-Agent",
    Accept: "application/json",
    "User-Agent": "scout/1.0",
  },
});
const body = await r.json();
console.log(body.user_agent);
console.log(body.ja4, body.akamai_hash);
