#!/bin/sh
# What a rejected directive looks like: 418, empty body, one X-Tip-Error header per issue.
# Run: sh ca-shell-curl-errors.sh
# Prints: the response headers, including X-Tip-Error-Count and each X-Tip-Error.
curl -s http://localhost:8080/ca.pem -o tip-ca.pem
curl -s -i --proxy http://localhost:8080 --cacert tip-ca.pem \
  -H "X-Tip-Browser: Safari" -H "X-Tip-Timeout: soon" \
  https://tls.browserleaks.com/json
