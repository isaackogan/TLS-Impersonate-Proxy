#!/bin/sh
# Pin one exact identity: pick an entry from /profiles and send its id as X-Tip-Profile.
# Run: sh ca-shell-curl-profile.sh
# Prints: the catalogue entry for Edge on Windows, then the User-Agent the destination saw.
curl -s http://localhost:8080/ca.pem -o tip-ca.pem
PROFILE=$(curl -s http://localhost:8080/profiles | jq -c '.profiles[] | select(.browser == "Edge" and .os == "Windows")')
echo "$PROFILE"
curl -s --proxy http://localhost:8080 --cacert tip-ca.pem \
  -H "X-Tip-Profile: $(echo "$PROFILE" | jq -r .id)" \
  https://tls.browserleaks.com/json | jq -r .user_agent
