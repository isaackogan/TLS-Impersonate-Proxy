#!/bin/sh
# Chrome fingerprint through TIP with curl in plain mode.
# Run: sh plain-shell-curl-basic.sh
# Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
curl -s --proxy http://localhost:8080 \
  -H "X-Tip-Scheme: https" -H "X-Tip-Browser: Chrome" -H "X-Tip-Os: Windows" \
  http://tls.browserleaks.com/json
