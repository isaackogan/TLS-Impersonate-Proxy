// Let TIP infer the browser from your User-Agent with X-Tip-Match, and keep that User-Agent on the wire.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && NODE_EXTRA_CA_CERTS=tip-ca.pem node ca-node-fetch-match.js
// Prints: your Firefox User-Agent unchanged, with a Firefox TLS and HTTP/2 fingerprint underneath it.
import { ProxyAgent } from "undici";

const r = await fetch("https://tls.browserleaks.com/json", {
  dispatcher: new ProxyAgent("http://localhost:8080"),
  headers: {
    "X-Tip-Match": "true",
    "X-Tip-Keep": "User-Agent",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
  },
});
const body = await r.json();
console.log(body.user_agent);
console.log(body.ja4, body.akamai_hash);
