// Chrome fingerprint through a TIP that requires proxy authentication; credentials live in the proxy URL.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && NODE_EXTRA_CA_CERTS=tip-ca.pem node ca-node-fetch-auth.js
// Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import { ProxyAgent } from "undici";

const r = await fetch("https://tls.browserleaks.com/json", {
  dispatcher: new ProxyAgent("http://alice:secret@localhost:8080"),
  headers: { "X-Tip-Browser": "Chrome", "X-Tip-Os": "Windows" },
});
const body = await r.json();
console.log(body.user_agent);
console.log(body.ja4, body.akamai_hash);
