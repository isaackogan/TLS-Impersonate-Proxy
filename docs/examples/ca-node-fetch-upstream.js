// Chrome fingerprint through TIP, then out through an upstream SOCKS5 proxy named by X-Tip-Proxy.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && NODE_EXTRA_CA_CERTS=tip-ca.pem node ca-node-fetch-upstream.js
// Prints: the egress IP the destination saw, then the user agent and fingerprints.
import { ProxyAgent } from "undici";

const r = await fetch("https://tls.browserleaks.com/json", {
  dispatcher: new ProxyAgent("http://localhost:8080"),
  headers: {
    "X-Tip-Browser": "Chrome",
    "X-Tip-Proxy": "socks5://user:pass@residential.example:1080",
  },
});
const body = await r.json();
console.log(body.ip);
console.log(body.user_agent);
console.log(body.ja4, body.akamai_hash);
