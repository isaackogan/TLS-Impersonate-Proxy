// Chrome fingerprint through TIP with net/http in CA mode.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && go run ca-go-nethttp-basic.go
// Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	req, _ := http.NewRequest("GET", "https://tls.browserleaks.com/json", nil)
	req.Header.Set("X-Tip-Browser", "Chrome")
	req.Header.Set("X-Tip-Os", "Windows")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	fmt.Println(body["user_agent"])
	fmt.Println(body["ja4"], body["akamai_hash"])
}
