# Chrome fingerprint through TIP with Net::HTTP in plain mode.
# Run: ruby plain-ruby-nethttp-basic.rb
# Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
require "net/http"

http = Net::HTTP.new("tls.browserleaks.com", 80, "localhost", 8080)
puts http.get("/json", { "X-Tip-Scheme" => "https", "X-Tip-Browser" => "Chrome", "X-Tip-Os" => "Windows" }).body
