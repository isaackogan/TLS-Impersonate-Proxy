#!/bin/sh
# Chrome fingerprint through TIP with curl in CA mode.
# Run: sh ca-shell-curl-basic.sh
# Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
curl -s http://localhost:8080/ca.pem -o tip-ca.pem
curl -s --proxy http://localhost:8080 --cacert tip-ca.pem \
  -H "X-Tip-Browser: Chrome" -H "X-Tip-Os: Windows" \
  https://tls.browserleaks.com/json
