// Chrome fingerprint through TIP with reqwest in plain mode.
// Run: cargo run (reqwest with the "json" feature, tokio with "full")
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("http://localhost:8080")?)
        .build()?;
    let body = client
        .get("http://tls.browserleaks.com/json")
        .header("X-Tip-Scheme", "https")
        .header("X-Tip-Browser", "Chrome")
        .header("X-Tip-Os", "Windows")
        .send()
        .await?
        .text()
        .await?;
    println!("{body}");
    Ok(())
}
