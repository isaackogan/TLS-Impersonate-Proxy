// Firefox fingerprint through TIP with axios in plain mode.
// Run: node plain-node-axios-basic.js
// Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import axios from "axios";

const r = await axios.get("http://tls.browserleaks.com/json", {
  proxy: { host: "localhost", port: 8080 },
  headers: { "X-Tip-Scheme": "https", "X-Tip-Browser": "Firefox", "X-Tip-Os": "Linux" },
});
console.log(r.data.user_agent);
console.log(r.data.ja4, r.data.akamai_hash);
