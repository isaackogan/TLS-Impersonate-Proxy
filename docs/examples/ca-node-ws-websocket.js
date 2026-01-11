// A WebSocket through TIP's MITM tunnel with ws in CA mode.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && node ca-node-ws-websocket.js
// Prints: the echoed message.
import fs from "node:fs";
import WebSocket from "ws";
import { HttpsProxyAgent } from "https-proxy-agent";

const agent = new HttpsProxyAgent("http://localhost:8080", { ca: fs.readFileSync("tip-ca.pem") });
const ws = new WebSocket("wss://echo.websocket.org", { agent, headers: { "X-Tip-Browser": "Chrome" } });
ws.on("open", () => ws.send("hello through tip"));
ws.on("message", (data) => {
  console.log(data.toString());
  ws.close();
});
