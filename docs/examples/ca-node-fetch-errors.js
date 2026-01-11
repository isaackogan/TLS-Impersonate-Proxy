// What a rejected directive looks like: 418, empty body, one X-Tip-Error header per issue.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && NODE_EXTRA_CA_CERTS=tip-ca.pem node ca-node-fetch-errors.js
// Prints: 418, then the X-Tip-Error values joined by commas.
import { ProxyAgent } from "undici";

const r = await fetch("https://tls.browserleaks.com/json", {
  dispatcher: new ProxyAgent("http://localhost:8080"),
  headers: { "X-Tip-Browser": "Safari", "X-Tip-Timeout": "soon" },
});
console.log(r.status);
console.log(r.headers.get("x-tip-error"));
