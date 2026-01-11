// Chrome fingerprint through TIP with got in plain mode.
// Run: node plain-node-got-basic.js
// Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import got from "got";
import { HttpProxyAgent } from "hpagent";

const body = await got("http://tls.browserleaks.com/json", {
  agent: { http: new HttpProxyAgent({ proxy: "http://localhost:8080" }) },
  headers: { "X-Tip-Scheme": "https", "X-Tip-Browser": "Chrome", "X-Tip-Os": "IOS" },
}).json();
console.log(body.user_agent);
console.log(body.ja4, body.akamai_hash);
