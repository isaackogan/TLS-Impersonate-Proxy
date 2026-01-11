#!/bin/sh
# Chrome TLS and HTTP/2 fingerprint while keeping curl's own Accept and User-Agent, via X-Tip-Keep.
# Run: sh ca-shell-curl-keep.sh
# Prints: the JSON the destination returned; user_agent is scout/1.0, the fingerprints are Chrome's.
curl -s http://localhost:8080/ca.pem -o tip-ca.pem
curl -s --proxy http://localhost:8080 --cacert tip-ca.pem \
  -H "X-Tip-Browser: Chrome" -H "X-Tip-Keep: Accept, User-Agent" \
  -H "Accept: application/json" -A "scout/1.0" \
  https://tls.browserleaks.com/json
