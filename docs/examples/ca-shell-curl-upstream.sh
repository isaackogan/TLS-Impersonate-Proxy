#!/bin/sh
# Chrome fingerprint through TIP, then out through an upstream SOCKS5 proxy named by X-Tip-Proxy.
# Run: sh ca-shell-curl-upstream.sh
# Prints: the JSON the destination returned; ip shows the upstream proxy's egress.
curl -s http://localhost:8080/ca.pem -o tip-ca.pem
curl -s --proxy http://localhost:8080 --cacert tip-ca.pem \
  -H "X-Tip-Browser: Chrome" \
  -H "X-Tip-Proxy: socks5://user:pass@residential.example:1080" \
  https://tls.browserleaks.com/json
