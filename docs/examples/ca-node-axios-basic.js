// Firefox fingerprint through TIP with axios in CA mode (https-proxy-agent carries the CA).
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && node ca-node-axios-basic.js
// Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import fs from "node:fs";
import axios from "axios";
import { HttpsProxyAgent } from "https-proxy-agent";

const agent = new HttpsProxyAgent("http://localhost:8080", { ca: fs.readFileSync("tip-ca.pem") });
const r = await axios.get("https://tls.browserleaks.com/json", {
  httpsAgent: agent,
  proxy: false,
  headers: { "X-Tip-Browser": "Firefox", "X-Tip-Os": "Linux" },
});
console.log(r.data.user_agent);
console.log(r.data.ja4, r.data.akamai_hash);
