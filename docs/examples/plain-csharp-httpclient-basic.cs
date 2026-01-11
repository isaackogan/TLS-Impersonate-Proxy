// Chrome fingerprint through TIP with HttpClient in plain mode.
// Run: dotnet run plain-csharp-httpclient-basic.cs
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
using System.Net;

var handler = new HttpClientHandler { Proxy = new WebProxy("http://localhost:8080"), UseProxy = true };
using var client = new HttpClient(handler);
client.DefaultRequestHeaders.Add("X-Tip-Scheme", "https");
client.DefaultRequestHeaders.Add("X-Tip-Browser", "Chrome");
client.DefaultRequestHeaders.Add("X-Tip-Os", "Windows");
Console.WriteLine(await client.GetStringAsync("http://tls.browserleaks.com/json"));
