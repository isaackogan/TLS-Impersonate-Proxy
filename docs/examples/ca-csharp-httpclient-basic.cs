// Chrome fingerprint through TIP with HttpClient in CA mode; the CA is trusted for this handler only.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && dotnet run ca-csharp-httpclient-basic.cs
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
using System.Net;
using System.Security.Cryptography.X509Certificates;

var ca = X509CertificateLoader.LoadCertificateFromFile("tip-ca.pem");
var handler = new HttpClientHandler { Proxy = new WebProxy("http://localhost:8080"), UseProxy = true };
handler.ServerCertificateCustomValidationCallback = (_, cert, chain, _) =>
{
    chain!.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(ca);
    return chain.Build(cert!);
};
using var client = new HttpClient(handler);
client.DefaultRequestHeaders.Add("X-Tip-Browser", "Chrome");
client.DefaultRequestHeaders.Add("X-Tip-Os", "Windows");
Console.WriteLine(await client.GetStringAsync("https://tls.browserleaks.com/json"));
