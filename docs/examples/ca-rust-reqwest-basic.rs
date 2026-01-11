// Chrome fingerprint through TIP with reqwest in CA mode.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && cargo run (reqwest with the "json" feature, tokio with "full")
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let ca = reqwest::Certificate::from_pem(&std::fs::read("tip-ca.pem").unwrap())?;
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("http://localhost:8080")?)
        .add_root_certificate(ca)
        .build()?;
    let body = client
        .get("https://tls.browserleaks.com/json")
        .header("X-Tip-Browser", "Chrome")
        .header("X-Tip-Os", "Windows")
        .send()
        .await?
        .text()
        .await?;
    println!("{body}");
    Ok(())
}
