// Chrome fingerprint over HTTP/3 upstream with X-Tip-ForceHttp: 3. HTTP/3 needs no upstream proxy or a SOCKS5 one.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && go run ca-go-nethttp-http3.go
// Prints: the client-side protocol (HTTP/1.1 to TIP) and the first line of the destination's body.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

func main() {
	pem, _ := os.ReadFile("tip-ca.pem")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	proxy, _ := url.Parse("http://localhost:8080")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: pool}}}
	req, _ := http.NewRequest("GET", "https://cloudflare-quic.com/", nil)
	req.Header.Set("X-Tip-Browser", "Chrome")
	req.Header.Set("X-Tip-ForceHttp", "3")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	first, _ := bufio.NewReader(resp.Body).ReadString('\n')
	fmt.Println(resp.Proto)
	fmt.Print(first)
}
