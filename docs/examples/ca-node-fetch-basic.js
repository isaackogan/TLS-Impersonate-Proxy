// Chrome fingerprint through TIP with Node's built-in fetch in CA mode (undici ProxyAgent).
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && NODE_EXTRA_CA_CERTS=tip-ca.pem node ca-node-fetch-basic.js
// Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import { ProxyAgent } from "undici";

const r = await fetch("https://tls.browserleaks.com/json", {
  dispatcher: new ProxyAgent("http://localhost:8080"),
  headers: { "X-Tip-Browser": "Chrome", "X-Tip-Os": "Windows" },
});
const body = await r.json();
console.log(body.user_agent);
console.log(body.ja4, body.akamai_hash);
