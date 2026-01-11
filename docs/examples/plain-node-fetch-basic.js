// Chrome fingerprint through TIP with Node's built-in fetch in plain mode.
// Run: node plain-node-fetch-basic.js
// Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import { ProxyAgent } from "undici";

const r = await fetch("http://tls.browserleaks.com/json", {
  dispatcher: new ProxyAgent("http://localhost:8080"),
  headers: { "X-Tip-Scheme": "https", "X-Tip-Browser": "Chrome", "X-Tip-Os": "Windows" },
});
const body = await r.json();
console.log(body.user_agent);
console.log(body.ja4, body.akamai_hash);
