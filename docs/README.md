# Threading TIP through your client

TIP is an HTTP proxy. Every library below already knows how to use one. The only decisions are which mode to use and how to load the CA.

CA mode is preferred: your code keeps its `https://` URLs and only trusts one extra certificate. Plain mode sends `http://` to TIP with `X-Tip-Scheme: https` and needs no certificate at all, but the hop from your client to TIP is cleartext, so it belongs on a private network.

| Language | Library | CA mode | Plain mode | More |
|---|---|---|---|---|
| Python | requests | [basic](examples/ca-python-requests-basic.py) | [basic](examples/plain-python-requests-basic.py) | [upstream](examples/ca-python-requests-upstream.py), [keep](examples/ca-python-requests-keep.py), [settings](examples/ca-python-requests-settings.py), [random](examples/ca-python-requests-random.py), [match](examples/ca-python-requests-match.py), [errors](examples/ca-python-requests-errors.py), [auth](examples/ca-python-requests-auth.py), [profile](examples/ca-python-requests-profile.py) |
| Python | httpx | [basic](examples/ca-python-httpx-basic.py) | [basic](examples/plain-python-httpx-basic.py) | |
| Python | aiohttp | [basic](examples/ca-python-aiohttp-basic.py) | [basic](examples/plain-python-aiohttp-basic.py) | |
| Python | websockets | [websocket](examples/ca-python-websockets-websocket.py) | | |
| Node | fetch | [basic](examples/ca-node-fetch-basic.js) | [basic](examples/plain-node-fetch-basic.js) | [upstream](examples/ca-node-fetch-upstream.js), [keep](examples/ca-node-fetch-keep.js), [settings](examples/ca-node-fetch-settings.js), [random](examples/ca-node-fetch-random.js), [match](examples/ca-node-fetch-match.js), [errors](examples/ca-node-fetch-errors.js), [auth](examples/ca-node-fetch-auth.js), [profile](examples/ca-node-fetch-profile.js) |
| Node | axios | [basic](examples/ca-node-axios-basic.js) | [basic](examples/plain-node-axios-basic.js) | |
| Node | got | [basic](examples/ca-node-got-basic.js) | [basic](examples/plain-node-got-basic.js) | |
| Node | ws | [websocket](examples/ca-node-ws-websocket.js) | | |
| Go | net/http | [basic](examples/ca-go-nethttp-basic.go) | [basic](examples/plain-go-nethttp-basic.go) | [http3](examples/ca-go-nethttp-http3.go) |
| Java | OkHttp | [basic](examples/ca-java-okhttp-basic.java) | [basic](examples/plain-java-okhttp-basic.java) | |
| C# | HttpClient | [basic](examples/ca-csharp-httpclient-basic.cs) | [basic](examples/plain-csharp-httpclient-basic.cs) | |
| Ruby | Net::HTTP | [basic](examples/ca-ruby-nethttp-basic.rb) | [basic](examples/plain-ruby-nethttp-basic.rb) | |
| PHP | Guzzle | [basic](examples/ca-php-guzzle-basic.php) | [basic](examples/plain-php-guzzle-basic.php) | |
| Rust | reqwest | [basic](examples/ca-rust-reqwest-basic.rs) | [basic](examples/plain-rust-reqwest-basic.rs) | |
| Shell | curl | [basic](examples/ca-shell-curl-basic.sh) | [basic](examples/plain-shell-curl-basic.sh) | [upstream](examples/ca-shell-curl-upstream.sh), [keep](examples/ca-shell-curl-keep.sh), [settings](examples/ca-shell-curl-settings.sh), [errors](examples/ca-shell-curl-errors.sh), [auth](examples/ca-shell-curl-auth.sh), [profile](examples/ca-shell-curl-profile.sh) |

Every example targets `https://tls.browserleaks.com/json`, which reports the User-Agent, the JA4 TLS fingerprint and the HTTP/2 fingerprint it observed, so the output proves the impersonation rather than just a status code. Fetch the CA once with `curl -s http://localhost:8080/ca.pem -o tip-ca.pem`.

## Loading the CA

| Runtime | How |
|---|---|
| Python requests | `verify="tip-ca.pem"` or `REQUESTS_CA_BUNDLE=tip-ca.pem` |
| Python httpx | `verify="tip-ca.pem"` |
| Python aiohttp | `ssl.create_default_context(cafile="tip-ca.pem")` |
| Node | `NODE_EXTRA_CA_CERTS=tip-ca.pem`, or `ca:` on the agent |
| Go | `RootCAs` on the transport, or `SSL_CERT_FILE=tip-ca.pem` on Linux |
| Java | `keytool -importcert` into a truststore, then `-Djavax.net.ssl.trustStore` |
| C# | `X509ChainTrustMode.CustomRootTrust` in the validation callback |
| Ruby | `http.ca_file = "tip-ca.pem"` |
| PHP Guzzle | `"verify" => "tip-ca.pem"` |
| Rust reqwest | `add_root_certificate(Certificate::from_pem(...))` |
| curl | `--cacert tip-ca.pem` |
| Debian-based image | copy to `/usr/local/share/ca-certificates/tip.crt`, run `update-ca-certificates` |

## Choosing an identity

`GET /profiles`, on the proxy port or the admin port, lists every browser and OS TIP can impersonate. Each entry has a stable `id`, the exact `userAgent` it will send and, for Chrome and Edge, the client hints that go with it. Send `X-Tip-Profile: <id>` instead of `X-Tip-Browser` and `X-Tip-Os` to pin one entry, which is the right tool when something on your side is bound to the User-Agent, such as a request signature. The `revision` field is the response's `ETag`, so a client can poll with `If-None-Match` and refetch only when the profiles change. An id TIP no longer knows is a `418` whose `X-Tip-Profiles-Revision` header says which revision to fetch.

## Python

### requests

<!-- example: ca-python-requests-basic.py -->
```python
# Chrome fingerprint through TIP in CA mode: the client trusts TIP's CA so https:// works unchanged.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-requests-basic.py
# Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import requests

TIP = "http://localhost:8080"

r = requests.get(
    "https://tls.browserleaks.com/json",
    proxies={"http": TIP, "https": TIP},
    verify="tip-ca.pem",
    headers={"X-Tip-Browser": "Chrome", "X-Tip-Os": "Windows"},
)
body = r.json()
print(body["user_agent"])
print(body["ja4"], body["akamai_hash"])
```

<!-- example: plain-python-requests-basic.py -->
```python
# Chrome fingerprint through TIP in plain mode: http:// to TIP, X-Tip-Scheme makes TIP speak TLS upstream.
# Run: python3 plain-python-requests-basic.py
# Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import requests

TIP = "http://localhost:8080"

r = requests.get(
    "http://tls.browserleaks.com/json",
    proxies={"http": TIP},
    headers={"X-Tip-Scheme": "https", "X-Tip-Browser": "Chrome", "X-Tip-Os": "Windows"},
)
body = r.json()
print(body["user_agent"])
print(body["ja4"], body["akamai_hash"])
```

`requests` reads `proxies` per scheme, so both keys point at TIP in CA mode and only `http` in plain mode.

### httpx

<!-- example: ca-python-httpx-basic.py -->
```python
# Firefox fingerprint through TIP with httpx in CA mode.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-httpx-basic.py
# Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import httpx

with httpx.Client(proxy="http://localhost:8080", verify="tip-ca.pem") as client:
    r = client.get(
        "https://tls.browserleaks.com/json",
        headers={"X-Tip-Browser": "Firefox", "X-Tip-Os": "MacOS"},
    )
body = r.json()
print(body["user_agent"])
print(body["ja4"], body["akamai_hash"])
```

<!-- example: plain-python-httpx-basic.py -->
```python
# Firefox fingerprint through TIP with httpx in plain mode.
# Run: python3 plain-python-httpx-basic.py
# Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import httpx

with httpx.Client(proxy="http://localhost:8080") as client:
    r = client.get(
        "http://tls.browserleaks.com/json",
        headers={"X-Tip-Scheme": "https", "X-Tip-Browser": "Firefox", "X-Tip-Os": "MacOS"},
    )
body = r.json()
print(body["user_agent"])
print(body["ja4"], body["akamai_hash"])
```

### aiohttp

<!-- example: ca-python-aiohttp-basic.py -->
```python
# Chrome fingerprint through TIP with aiohttp in CA mode.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-aiohttp-basic.py
# Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import asyncio
import ssl

import aiohttp


async def main():
    ctx = ssl.create_default_context(cafile="tip-ca.pem")
    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://tls.browserleaks.com/json",
            proxy="http://localhost:8080",
            ssl=ctx,
            headers={"X-Tip-Browser": "Chrome", "X-Tip-Os": "Android"},
        ) as r:
            body = await r.json()
    print(body["user_agent"])
    print(body["ja4"], body["akamai_hash"])


asyncio.run(main())
```

<!-- example: plain-python-aiohttp-basic.py -->
```python
# Chrome fingerprint through TIP with aiohttp in plain mode.
# Run: python3 plain-python-aiohttp-basic.py
# Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import asyncio

import aiohttp


async def main():
    async with aiohttp.ClientSession() as session:
        async with session.get(
            "http://tls.browserleaks.com/json",
            proxy="http://localhost:8080",
            headers={"X-Tip-Scheme": "https", "X-Tip-Browser": "Chrome", "X-Tip-Os": "Android"},
        ) as r:
            body = await r.json()
    print(body["user_agent"])
    print(body["ja4"], body["akamai_hash"])


asyncio.run(main())
```

`aiohttp` takes the proxy per request and the CA through an `ssl.SSLContext`.

### websockets

<!-- example: ca-python-websockets-websocket.py -->
```python
# A WebSocket through TIP's MITM tunnel with the websockets library in CA mode.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && python3 ca-python-websockets-websocket.py
# Prints: the echoed message.
import asyncio
import ssl

from python_socks.async_.asyncio import Proxy
from websockets.asyncio.client import connect


async def main():
    ctx = ssl.create_default_context(cafile="tip-ca.pem")
    proxy = Proxy.from_url("http://localhost:8080")
    sock = await proxy.connect(dest_host="echo.websocket.org", dest_port=443)
    async with connect(
        "wss://echo.websocket.org",
        sock=sock,
        ssl=ctx,
        server_hostname="echo.websocket.org",
        additional_headers={"X-Tip-Browser": "Chrome"},
    ) as ws:
        await ws.send("hello through tip")
        print(await ws.recv())


asyncio.run(main())
```

`websockets` has no proxy support of its own; `python-socks` opens the CONNECT tunnel and hands over the socket.

## Node

### fetch

<!-- example: ca-node-fetch-basic.js -->
```javascript
// Chrome fingerprint through TIP with Node's built-in fetch in CA mode (undici ProxyAgent).
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && NODE_EXTRA_CA_CERTS=tip-ca.pem node ca-node-fetch-basic.js
// Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
import { ProxyAgent } from "undici";

const r = await fetch("https://tls.browserleaks.com/json", {
  dispatcher: new ProxyAgent("http://localhost:8080"),
  headers: { "X-Tip-Browser": "Chrome", "X-Tip-Os": "Windows" },
});
const body = await r.json();
console.log(body.user_agent);
console.log(body.ja4, body.akamai_hash);
```

<!-- example: plain-node-fetch-basic.js -->
```javascript
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
```

Node's built-in `fetch` ignores proxy environment variables; undici's `ProxyAgent` is the dispatcher that speaks CONNECT. The CA comes from `NODE_EXTRA_CA_CERTS`.

### axios

<!-- example: ca-node-axios-basic.js -->
```javascript
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
```

<!-- example: plain-node-axios-basic.js -->
```javascript
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
```

`axios` must be told `proxy: false` when an agent handles the proxy, otherwise it sends absolute-URI requests on its own and skips CONNECT.

### got

<!-- example: ca-node-got-basic.js -->
```javascript
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
```

<!-- example: plain-node-got-basic.js -->
```javascript
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
```

`got` takes agents per scheme through `hpagent` and the CA through `https.certificateAuthority`.

### ws

<!-- example: ca-node-ws-websocket.js -->
```javascript
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
```

## Go

### net/http

<!-- example: ca-go-nethttp-basic.go -->
```go
// Chrome fingerprint through TIP with net/http in CA mode.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && go run ca-go-nethttp-basic.go
// Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

func main() {
	pem, _ := os.ReadFile("tip-ca.pem")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	proxy, _ := url.Parse("http://localhost:8080")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: pool}}}
	req, _ := http.NewRequest("GET", "https://tls.browserleaks.com/json", nil)
	req.Header.Set("X-Tip-Browser", "Chrome")
	req.Header.Set("X-Tip-Os", "Windows")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	fmt.Println(body["user_agent"])
	fmt.Println(body["ja4"], body["akamai_hash"])
}
```

<!-- example: plain-go-nethttp-basic.go -->
```go
// Chrome fingerprint through TIP with net/http in plain mode.
// Run: go run plain-go-nethttp-basic.go
// Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

func main() {
	proxy, _ := url.Parse("http://localhost:8080")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	req, _ := http.NewRequest("GET", "http://tls.browserleaks.com/json", nil)
	req.Header.Set("X-Tip-Scheme", "https")
	req.Header.Set("X-Tip-Browser", "Chrome")
	req.Header.Set("X-Tip-Os", "Windows")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	fmt.Println(body["user_agent"])
	fmt.Println(body["ja4"], body["akamai_hash"])
}
```

One transport carries both `Proxy` and `RootCAs`. `http.ProxyURL` sends proxy credentials on CONNECT when the URL has them.

## Java

### OkHttp

<!-- example: ca-java-okhttp-basic.java -->
```java
// Chrome fingerprint through TIP with OkHttp in CA mode; the CA is imported into a truststore first.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && keytool -importcert -noprompt -alias tip -file tip-ca.pem -keystore tip.jks -storepass changeit && java -Djavax.net.ssl.trustStore=tip.jks -Djavax.net.ssl.trustStorePassword=changeit -cp okhttp.jar:okio.jar:kotlin-stdlib.jar ca-java-okhttp-basic.java
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
import java.net.InetSocketAddress;
import java.net.Proxy;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class Main {
    public static void main(String[] args) throws Exception {
        OkHttpClient client = new OkHttpClient.Builder()
            .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", 8080)))
            .build();
        Request request = new Request.Builder()
            .url("https://tls.browserleaks.com/json")
            .header("X-Tip-Browser", "Chrome")
            .header("X-Tip-Os", "Windows")
            .build();
        try (Response response = client.newCall(request).execute()) {
            System.out.println(response.body().string());
        }
    }
}
```

<!-- example: plain-java-okhttp-basic.java -->
```java
// Chrome fingerprint through TIP with OkHttp in plain mode.
// Run: java -cp okhttp.jar:okio.jar:kotlin-stdlib.jar plain-java-okhttp-basic.java
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
import java.net.InetSocketAddress;
import java.net.Proxy;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class Main {
    public static void main(String[] args) throws Exception {
        OkHttpClient client = new OkHttpClient.Builder()
            .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", 8080)))
            .build();
        Request request = new Request.Builder()
            .url("http://tls.browserleaks.com/json")
            .header("X-Tip-Scheme", "https")
            .header("X-Tip-Browser", "Chrome")
            .header("X-Tip-Os", "Windows")
            .build();
        try (Response response = client.newCall(request).execute()) {
            System.out.println(response.body().string());
        }
    }
}
```

Java trusts through a truststore, so the CA is imported with `keytool` and the JVM pointed at it.

## C#

### HttpClient

<!-- example: ca-csharp-httpclient-basic.cs -->
```csharp
// Chrome fingerprint through TIP with HttpClient in CA mode; the CA is trusted for this handler only.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && dotnet run ca-csharp-httpclient-basic.cs
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
using System.Net;
using System.Security.Cryptography.X509Certificates;

var ca = X509CertificateLoader.LoadCertificateFromFile("tip-ca.pem");
var handler = new HttpClientHandler { Proxy = new WebProxy("http://localhost:8080"), UseProxy = true };
handler.ServerCertificateCustomValidationCallback = (_, cert, chain, _) =>
{
    chain!.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(ca);
    return chain.Build(cert!);
};
using var client = new HttpClient(handler);
client.DefaultRequestHeaders.Add("X-Tip-Browser", "Chrome");
client.DefaultRequestHeaders.Add("X-Tip-Os", "Windows");
Console.WriteLine(await client.GetStringAsync("https://tls.browserleaks.com/json"));
```

<!-- example: plain-csharp-httpclient-basic.cs -->
```csharp
// Chrome fingerprint through TIP with HttpClient in plain mode.
// Run: dotnet run plain-csharp-httpclient-basic.cs
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
using System.Net;

var handler = new HttpClientHandler { Proxy = new WebProxy("http://localhost:8080"), UseProxy = true };
using var client = new HttpClient(handler);
client.DefaultRequestHeaders.Add("X-Tip-Scheme", "https");
client.DefaultRequestHeaders.Add("X-Tip-Browser", "Chrome");
client.DefaultRequestHeaders.Add("X-Tip-Os", "Windows");
Console.WriteLine(await client.GetStringAsync("http://tls.browserleaks.com/json"));
```

`CustomRootTrust` limits the extra trust to this handler instead of the machine store.

## Ruby

### Net::HTTP

<!-- example: ca-ruby-nethttp-basic.rb -->
```ruby
# Chrome fingerprint through TIP with Net::HTTP in CA mode.
# Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && ruby ca-ruby-nethttp-basic.rb
# Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
require "net/http"
require "openssl"

http = Net::HTTP.new("tls.browserleaks.com", 443, "localhost", 8080)
http.use_ssl = true
http.ca_file = "tip-ca.pem"
http.verify_mode = OpenSSL::SSL::VERIFY_PEER
puts http.get("/json", { "X-Tip-Browser" => "Chrome", "X-Tip-Os" => "Windows" }).body
```

<!-- example: plain-ruby-nethttp-basic.rb -->
```ruby
# Chrome fingerprint through TIP with Net::HTTP in plain mode.
# Run: ruby plain-ruby-nethttp-basic.rb
# Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
require "net/http"

http = Net::HTTP.new("tls.browserleaks.com", 80, "localhost", 8080)
puts http.get("/json", { "X-Tip-Scheme" => "https", "X-Tip-Browser" => "Chrome", "X-Tip-Os" => "Windows" }).body
```

`Net::HTTP.new` takes the proxy host and port as positional arguments after the destination.

## PHP

### Guzzle

<!-- example: ca-php-guzzle-basic.php -->
```php
<?php
// Chrome fingerprint through TIP with Guzzle in CA mode.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && php ca-php-guzzle-basic.php
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
require "vendor/autoload.php";

$client = new GuzzleHttp\Client(["proxy" => "http://localhost:8080", "verify" => "tip-ca.pem"]);
$response = $client->get("https://tls.browserleaks.com/json", [
    "headers" => ["X-Tip-Browser" => "Chrome", "X-Tip-Os" => "Windows"],
]);
echo $response->getBody(), "\n";
```

<!-- example: plain-php-guzzle-basic.php -->
```php
<?php
// Chrome fingerprint through TIP with Guzzle in plain mode.
// Run: php plain-php-guzzle-basic.php
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
require "vendor/autoload.php";

$client = new GuzzleHttp\Client(["proxy" => "http://localhost:8080"]);
$response = $client->get("http://tls.browserleaks.com/json", [
    "headers" => ["X-Tip-Scheme" => "https", "X-Tip-Browser" => "Chrome", "X-Tip-Os" => "Windows"],
]);
echo $response->getBody(), "\n";
```

## Rust

### reqwest

<!-- example: ca-rust-reqwest-basic.rs -->
```rust
// Chrome fingerprint through TIP with reqwest in CA mode.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && cargo run (reqwest with the "json" feature, tokio with "full")
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let ca = reqwest::Certificate::from_pem(&std::fs::read("tip-ca.pem").unwrap())?;
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("http://localhost:8080")?)
        .add_root_certificate(ca)
        .build()?;
    let body = client
        .get("https://tls.browserleaks.com/json")
        .header("X-Tip-Browser", "Chrome")
        .header("X-Tip-Os", "Windows")
        .send()
        .await?
        .text()
        .await?;
    println!("{body}");
    Ok(())
}
```

<!-- example: plain-rust-reqwest-basic.rs -->
```rust
// Chrome fingerprint through TIP with reqwest in plain mode.
// Run: cargo run (reqwest with the "json" feature, tokio with "full")
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("http://localhost:8080")?)
        .build()?;
    let body = client
        .get("http://tls.browserleaks.com/json")
        .header("X-Tip-Scheme", "https")
        .header("X-Tip-Browser", "Chrome")
        .header("X-Tip-Os", "Windows")
        .send()
        .await?
        .text()
        .await?;
    println!("{body}");
    Ok(())
}
```

## Shell

### curl

<!-- example: ca-shell-curl-basic.sh -->
```sh
#!/bin/sh
# Chrome fingerprint through TIP with curl in CA mode.
# Run: sh ca-shell-curl-basic.sh
# Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
curl -s http://localhost:8080/ca.pem -o tip-ca.pem
curl -s --proxy http://localhost:8080 --cacert tip-ca.pem \
  -H "X-Tip-Browser: Chrome" -H "X-Tip-Os: Windows" \
  https://tls.browserleaks.com/json
```

<!-- example: plain-shell-curl-basic.sh -->
```sh
#!/bin/sh
# Chrome fingerprint through TIP with curl in plain mode.
# Run: sh plain-shell-curl-basic.sh
# Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
curl -s --proxy http://localhost:8080 \
  -H "X-Tip-Scheme: https" -H "X-Tip-Browser: Chrome" -H "X-Tip-Os: Windows" \
  http://tls.browserleaks.com/json
```

## Scenarios

| Scenario | Shows | Examples |
|---|---|---|
| upstream | `X-Tip-Proxy` sends the impersonated connection out through your own SOCKS5 or HTTP proxy | [python](examples/ca-python-requests-upstream.py), [node](examples/ca-node-fetch-upstream.js), [curl](examples/ca-shell-curl-upstream.sh) |
| keep | `X-Tip-Keep` hands named headers back to you after the profile has set its own | [python](examples/ca-python-requests-keep.py), [node](examples/ca-node-fetch-keep.js), [curl](examples/ca-shell-curl-keep.sh) |
| settings | `X-Tip-Http2Settings` as a cookie-style key-value list | [python](examples/ca-python-requests-settings.py), [node](examples/ca-node-fetch-settings.js), [curl](examples/ca-shell-curl-settings.sh) |
| random | a choice list in `X-Tip-Browser` or `X-Tip-Os`, resolved once per connection | [python](examples/ca-python-requests-random.py), [node](examples/ca-node-fetch-random.js) |
| profile | an `id` from `GET /profiles` in `X-Tip-Profile`, pinning one exact User-Agent and the fingerprint that goes with it | [python](examples/ca-python-requests-profile.py), [node](examples/ca-node-fetch-profile.js), [shell](examples/ca-shell-curl-profile.sh) |
| match | `X-Tip-Match` infers the browser family from your User-Agent | [python](examples/ca-python-requests-match.py), [node](examples/ca-node-fetch-match.js) |
| errors | the `418` response and its `X-Tip-Error` headers | [python](examples/ca-python-requests-errors.py), [node](examples/ca-node-fetch-errors.js), [curl](examples/ca-shell-curl-errors.sh) |
| auth | proxy credentials in the proxy URL | [python](examples/ca-python-requests-auth.py), [node](examples/ca-node-fetch-auth.js), [curl](examples/ca-shell-curl-auth.sh) |
| websocket | a WebSocket upgrade relayed through the MITM tunnel | [python](examples/ca-python-websockets-websocket.py), [node](examples/ca-node-ws-websocket.js) |
| http3 | `X-Tip-ForceHttp: 3` against an HTTP/3 endpoint | [go](examples/ca-go-nethttp-http3.go) |
