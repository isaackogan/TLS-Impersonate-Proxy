#!/bin/sh
# Chrome fingerprint through a TIP that requires proxy authentication; credentials live in the proxy URL.
# Run: sh ca-shell-curl-auth.sh
# Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
curl -s http://localhost:8080/ca.pem -o tip-ca.pem
curl -s --proxy http://alice:secret@localhost:8080 --cacert tip-ca.pem \
  -H "X-Tip-Browser: Chrome" -H "X-Tip-Os: Windows" \
  https://tls.browserleaks.com/json
