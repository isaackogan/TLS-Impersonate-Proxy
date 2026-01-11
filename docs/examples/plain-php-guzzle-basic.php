<?php
// Chrome fingerprint through TIP with Guzzle in plain mode.
// Run: php plain-php-guzzle-basic.php
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
require "vendor/autoload.php";

$client = new GuzzleHttp\Client(["proxy" => "http://localhost:8080"]);
$response = $client->get("http://tls.browserleaks.com/json", [
    "headers" => ["X-Tip-Scheme" => "https", "X-Tip-Browser" => "Chrome", "X-Tip-Os" => "Windows"],
]);
echo $response->getBody(), "\n";
