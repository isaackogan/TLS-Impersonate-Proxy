// Pin one exact identity. /profiles lists every browser and OS TIP can be, each with the User-Agent it will send and a stable id.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && NODE_EXTRA_CA_CERTS=tip-ca.pem node ca-node-fetch-profile.js
// Prints: the chosen profile's User-Agent twice: once from the catalogue, once as the destination saw it.
import { ProxyAgent } from "undici";

const TIP = "http://localhost:8080";

const { profiles } = await (await fetch(`${TIP}/profiles`)).json();
const profile = profiles.find((p) => p.browser === "Firefox" && p.os === "MacOS");
console.log(profile.userAgent);
const r = await fetch("https://tls.browserleaks.com/json", {
  dispatcher: new ProxyAgent(TIP),
  headers: { "X-Tip-Profile": profile.id },
});
console.log((await r.json()).user_agent);
