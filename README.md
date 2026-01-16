# TLS-Impersonate-Proxy: A light-weight MITM proxy for scraping

TLS Impersonate Proxy. Point any HTTP client at TIP as an ordinary HTTP proxy, describe the browser you want with `X-Tip-*` headers, and the destination sees that browser's TLS, HTTP/2 and header fingerprint. The response comes back untouched.

[![ci](https://github.com/isaackogan/tls-impersonate-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/isaackogan/tls-impersonate-proxy/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/isaackogan/tls-impersonate-proxy)](https://github.com/isaackogan/tls-impersonate-proxy/releases)

TIP replaces per-language fingerprint libraries with one network hop. It is built on [surf](https://github.com/enetx/surf) for the fingerprint, [goproxy](https://github.com/elazarl/goproxy) for the proxy, and [zog](https://github.com/Oudwins/zog) for validation. When a behaviour is in doubt, surf's behaviour is the specification.

## How it works

```
client ──(your library, your headers, X-Tip-*)──▶ TIP ──(Chrome 152 or Firefox 148 fingerprint)──▶ destination
                                                   │ validates X-Tip-*, builds a surf client, strips X-Tip-*
client ◀──────────(status, headers, body as sent)── TIP ◀──────────────────────────────────────── destination
```

## Quick start

```sh
docker run -d --name tip -p 8080:8080 -v tip-ca:/var/lib/tip \
  -v "$PWD/tip.yaml:/etc/tip/tip.yaml:ro" ghcr.io/isaackogan/tls-impersonate-proxy:1
  
curl -s http://localhost:8080/ca.pem -o tip-ca.pem

curl -s --proxy http://localhost:8080 --cacert tip-ca.pem \
  -H "X-Tip-Browser: Chrome" -H "X-Tip-Os: Windows" https://tls.browserleaks.com/json
```

An empty `tip.yaml` is a valid configuration. The last command prints the User-Agent, JA4 and HTTP/2 fingerprint the destination observed, which are Chrome's.

> [!IMPORTANT]
> In CA mode TIP terminates TLS with a certificate it signs. Your client must trust `/ca.pem`, or use plain mode below.

## Connection modes

| Mode | You send | TLS to TIP | CA needed | Use when |
|---|---|---|---|---|
| CA (preferred) | `https://…` | your client, trusting TIP's CA | yes | anywhere; URLs stay as they are |
| Plain | `http://…` plus `X-Tip-Scheme: https` | none | no | private networks where installing a CA is impractical |

> [!WARNING]
> Plain mode sends the request, its headers and cookies to TIP in cleartext.

## Directives

Every name is a surf identifier and matching is case-insensitive: `X-TIP-HTTP2SETTINGS: HEADERTABLESIZE=65536; ENABLEPUSH=0` is accepted.

| Header | Value | Effect |
|---|---|---|
| `X-Tip-Browser` | `Chrome`, `Firefox`, `Edge`, `Random`, or a list such as `Chrome,Edge` | the full profile: TLS ClientHello, HTTP/2 and HTTP/3 SETTINGS, header set and order. A list is chosen from once per connection. Edge is Chromium's fingerprint with Edge's User-Agent and brands, on every OS but iOS |
| `X-Tip-Os` | `Windows`, `MacOS`, `Linux`, `Android`, `IOS`, `Random`, or a list such as `IOS,Android` | the OS the profile claims; a list is chosen from once per connection, among the OSes the browser supports |
| `X-Tip-Profile` | an `id` from `GET /profiles` | one exact identity: the browser, OS, User-Agent and client hints the catalogue lists for it; replaces `Browser`, `Os` and `Match` |
| `X-Tip-Match` | `true` | infer `Browser` and `Os` from your User-Agent when `X-Tip-Browser` is absent; Safari, curl and library defaults get no impersonation |
| `X-Tip-Ja` | a surf JA preset such as `Chrome120PQ`, `Firefox148`, `Safari`, `Randomized` | the TLS ClientHello alone |
| `X-Tip-Http2Settings` | `HeaderTableSize=65536; EnablePush=0; …` | HTTP/2 SETTINGS and flow control |
| `X-Tip-Http3Settings` | `QpackMaxTableCapacity=65536; Grease=true; …` | HTTP/3 SETTINGS, in the order written |
| `X-Tip-ForceHttp` | `1`, `2`, `3` | the protocol to use upstream |
| `X-Tip-Proxy` | `socks5://user:pass@host:1080`, `http://…` | the upstream proxy for this fingerprint |
| `X-Tip-Timeout` | `15s` | time to response headers; only shortens the configured ceiling |
| `X-Tip-Dns` | `1.1.1.1:53` | the resolver |
| `X-Tip-DnsOverTls` | `Cloudflare`, `Google`, `Quad9`, … or `name@host:853` | DNS over TLS |
| `X-Tip-InterfaceAddr` | an IP or interface name | the local address to dial from |
| `X-Tip-SecureTls` | `true` | verify the destination's certificate |
| `X-Tip-DisableKeepAlive` | `true` | one connection per request |
| `X-Tip-H2c` | `true` | HTTP/2 cleartext |
| `X-Tip-Scheme` | `https` | plain mode: TIP opens TLS to the destination |
| `X-Tip-Keep` | `Accept, User-Agent` | headers the profile must not overwrite |

<details>
<summary>Grammar, header ownership and inference</summary>

| Shape | Syntax | Parsed as |
|---|---|---|
| token | `Chrome` | case-insensitive |
| list | `IOS,Android` | HTTP list syntax |
| key-value | `Key=Value; Key=Value` | `Cookie` header syntax; a flag is `Key=true`, and `Key=false` is accepted and ignored |
| boolean | `true`, `false`, `1`, `0` | Go's `strconv.ParseBool` |
| duration | `15s`, `1m30s`, `500ms` | Go's `time.ParseDuration` |
| URL | absolute with scheme | `net/url` |

When `X-Tip-Browser` applies, the profile owns User-Agent, Accept, Accept-Encoding, Accept-Language, Upgrade-Insecure-Requests, Priority, the `Sec-Fetch-*` and `sec-ch-ua*` families, and on POST also Cache-Control and Pragma. Cookie, Authorization, Referer, Origin, Content-Type and everything else you send pass through unchanged.

`X-Tip-Match` first compares your User-Agent byte-for-byte against the strings surf's profiles emit; a match pins browser and OS. Otherwise `Firefox/` or `FxiOS/` selects Firefox and `Chrome/`, `CriOS/` or `Chromium/` selects Chrome, with the OS read from the platform token. Explicit `X-Tip-Browser` and `X-Tip-Os` always win.

> [!TIP]
> `X-Tip-Keep: Accept, User-Agent` hands those headers back to you after the profile runs. With `X-Tip-Match: true` that gives your exact User-Agent a matching TLS and HTTP/2 fingerprint.

`GET /profiles` lists every identity TIP can take, with the exact User-Agent and client hints each one sends and a stable `id`. Pin one with `X-Tip-Profile` when something on your side, such as a request signature, is bound to the User-Agent that will go out. The listing's `revision` is also its `ETag`, and an id TIP no longer knows is a `418` naming the current revision in `X-Tip-Profiles-Revision`.

</details>

> [!NOTE]
> Every `X-Tip-*` header is removed before the request leaves TIP. Redirects, cookies and retries stay your library's job; TIP returns the destination's `3xx` and `Set-Cookie` as they are.

## Examples

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

| | Python | Node | Go | Java | C# | Ruby | PHP | Rust | Shell |
|---|---|---|---|---|---|---|---|---|---|
| CA mode | [requests](docs/examples/ca-python-requests-basic.py), [httpx](docs/examples/ca-python-httpx-basic.py), [aiohttp](docs/examples/ca-python-aiohttp-basic.py) | [fetch](docs/examples/ca-node-fetch-basic.js), [axios](docs/examples/ca-node-axios-basic.js), [got](docs/examples/ca-node-got-basic.js) | [net/http](docs/examples/ca-go-nethttp-basic.go) | [OkHttp](docs/examples/ca-java-okhttp-basic.java) | [HttpClient](docs/examples/ca-csharp-httpclient-basic.cs) | [Net::HTTP](docs/examples/ca-ruby-nethttp-basic.rb) | [Guzzle](docs/examples/ca-php-guzzle-basic.php) | [reqwest](docs/examples/ca-rust-reqwest-basic.rs) | [curl](docs/examples/ca-shell-curl-basic.sh) |
| Plain mode | [requests](docs/examples/plain-python-requests-basic.py), [httpx](docs/examples/plain-python-httpx-basic.py), [aiohttp](docs/examples/plain-python-aiohttp-basic.py) | [fetch](docs/examples/plain-node-fetch-basic.js), [axios](docs/examples/plain-node-axios-basic.js), [got](docs/examples/plain-node-got-basic.js) | [net/http](docs/examples/plain-go-nethttp-basic.go) | [OkHttp](docs/examples/plain-java-okhttp-basic.java) | [HttpClient](docs/examples/plain-csharp-httpclient-basic.cs) | [Net::HTTP](docs/examples/plain-ruby-nethttp-basic.rb) | [Guzzle](docs/examples/plain-php-guzzle-basic.php) | [reqwest](docs/examples/plain-rust-reqwest-basic.rs) | [curl](docs/examples/plain-shell-curl-basic.sh) |

Upstream proxies, kept headers, HTTP/2 settings, random OS, inference, error handling, proxy auth, WebSockets and HTTP/3 are in [docs/README.md](docs/README.md), one runnable file each under [docs/examples](docs/examples).

## Configuration

```yaml
directives:
  defaults: {Browser: Chrome, Os: Random}
  deny: [Proxy, InterfaceAddr]
auth:
  users: {alice: secret}
```

One YAML file, every key optional, unknown keys rejected at startup. [tip.example.yaml](docs/tip.example.yaml) lists every key with its default and is the reference.

## Observability

<details>
<summary>Metrics on the admin port, each collector switchable in <code>metrics.collectors</code></summary>

| Metric | Labels |
|---|---|
| `tip_requests_total`, `tip_requests_inflight` | `host`, `method`, `status`, `browser`, `route` |
| `tip_request_duration_seconds` | `host`, `route` |
| `tip_bandwidth_bytes_total` | `host`, `route`, `direction` |
| `tip_upstream_errors_total` | `host`, `kind` |
| `tip_validation_errors_total` | `directive` |
| `tip_clients_active`, `tip_client_builds_total`, `tip_client_evictions_total`, `tip_client_cache_hits_total`, `tip_client_cache_misses_total` | `browser`, `os` on builds |
| `tip_tunnels_total` | |

`metrics.routes` names URL patterns such as `/room/:room_id/*` so `route` becomes a bounded label, and `capture: [room_id]` adds the parameter as a label of its own.

> [!CAUTION]
> Captured route labels create one time series per distinct value.

</details>

<details>
<summary>Log fields, JSON on stdout</summary>

| Field | Meaning |
|---|---|
| `method`, `scheme`, `host`, `path`, `status` | the request as the client sent it and the status it received |
| `duration_ms`, `bytes_in`, `bytes_out` | from request parsed to body closed, and the bytes each way |
| `browser`, `os`, `route`, `client_key` | the resolved fingerprint, the matched route, and a hash of the cache key |
| `headers` | at `debug`, the outbound header list in transmission order, with `logging.redact` applied |

</details>

## Errors

A request whose directives fail validation never reaches the destination:

```
HTTP/1.1 418 I'm a teapot
Content-Length: 0
X-Tip-Error-Count: 2
X-Tip-Error: Browser: must be one of Chrome, Firefox
X-Tip-Error: Timeout: must be a duration such as 15s or 500ms
```

An upstream failure is a `502` with one `X-Tip-Error` naming the kind: `dial`, `tls`, `timeout`, `proxy` or `read`. A missing or wrong proxy credential is a `407`.

## Built on

[surf](https://github.com/enetx/surf), [goproxy](https://github.com/elazarl/goproxy), [zog](https://github.com/Oudwins/zog), [prometheus/client_golang](https://github.com/prometheus/client_golang). MIT.
