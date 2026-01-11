<?php
// Chrome fingerprint through TIP with Guzzle in CA mode.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && php ca-php-guzzle-basic.php
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
require "vendor/autoload.php";

$client = new GuzzleHttp\Client(["proxy" => "http://localhost:8080", "verify" => "tip-ca.pem"]);
$response = $client->get("https://tls.browserleaks.com/json", [
    "headers" => ["X-Tip-Browser" => "Chrome", "X-Tip-Os" => "Windows"],
]);
echo $response->getBody(), "\n";
