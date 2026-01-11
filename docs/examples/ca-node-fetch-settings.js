// Chrome fingerprint with explicit HTTP/2 SETTINGS, written as a cookie-style key-value list.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && NODE_EXTRA_CA_CERTS=tip-ca.pem node ca-node-fetch-settings.js
// Prints: the HTTP/2 fingerprint the destination derived from those SETTINGS.
import { ProxyAgent } from "undici";

const r = await fetch("https://tls.browserleaks.com/json", {
  dispatcher: new ProxyAgent("http://localhost:8080"),
  headers: {
    "X-Tip-Browser": "Chrome",
    "X-Tip-Http2Settings": "HeaderTableSize=65536; EnablePush=0; InitialWindowSize=6291456; MaxHeaderListSize=262144; ConnectionFlow=15663105",
  },
});
console.log((await r.json()).akamai_hash);
