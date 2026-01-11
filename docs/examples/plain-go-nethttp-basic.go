// Chrome fingerprint through TIP with net/http in plain mode.
// Run: go run plain-go-nethttp-basic.go
// Prints: the user agent, JA4 and HTTP/2 fingerprint the destination observed.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

func main() {
	proxy, _ := url.Parse("http://localhost:8080")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	req, _ := http.NewRequest("GET", "http://tls.browserleaks.com/json", nil)
	req.Header.Set("X-Tip-Scheme", "https")
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
