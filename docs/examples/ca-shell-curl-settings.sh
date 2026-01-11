#!/bin/sh
# Chrome fingerprint with explicit HTTP/2 SETTINGS, written as a cookie-style key-value list.
# Run: sh ca-shell-curl-settings.sh
# Prints: the JSON the destination returned; akamai_hash reflects those SETTINGS.
curl -s http://localhost:8080/ca.pem -o tip-ca.pem
curl -s --proxy http://localhost:8080 --cacert tip-ca.pem \
  -H "X-Tip-Browser: Chrome" \
  -H "X-Tip-Http2Settings: HeaderTableSize=65536; EnablePush=0; InitialWindowSize=6291456; MaxHeaderListSize=262144; ConnectionFlow=15663105" \
  https://tls.browserleaks.com/json
