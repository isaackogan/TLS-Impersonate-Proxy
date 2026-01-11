// Chrome fingerprint through TIP with got in CA mode.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && node ca-node-got-basic.js
// Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import fs from "node:fs";
import got from "got";
import { HttpsProxyAgent } from "hpagent";

const body = await got("https://tls.browserleaks.com/json", {
  agent: { https: new HttpsProxyAgent({ proxy: "http://localhost:8080" }) },
  https: { certificateAuthority: fs.readFileSync("tip-ca.pem") },
  headers: { "X-Tip-Browser": "Chrome", "X-Tip-Os": "IOS" },
}).json();
console.log(body.user_agent);
console.log(body.ja4, body.akamai_hash);
