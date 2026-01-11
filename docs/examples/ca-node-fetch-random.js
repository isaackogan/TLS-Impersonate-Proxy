// Firefox on a randomly chosen mobile OS. One dispatcher keeps one connection, and one connection keeps one OS.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && NODE_EXTRA_CA_CERTS=tip-ca.pem node ca-node-fetch-random.js
// Prints: three user agents; the OS is chosen once per connection, so they match within the dispatcher.
import { ProxyAgent } from "undici";

const dispatcher = new ProxyAgent("http://localhost:8080");
for (let i = 0; i < 3; i++) {
  const r = await fetch("https://tls.browserleaks.com/json", {
    dispatcher,
    headers: { "X-Tip-Browser": "Firefox", "X-Tip-Os": "IOS,Android" },
  });
  console.log((await r.json()).user_agent);
}
