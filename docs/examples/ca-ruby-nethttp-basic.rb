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
