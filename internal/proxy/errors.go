package proxy

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

var singleLine = strings.NewReplacer("\r", " ", "\n", " ")

func teapot(req *http.Request, issues directive.Issues) *http.Response {
	return synthetic(req, http.StatusTeapot, issues.Headers())
}

func badGateway(req *http.Request, d diagnosis) *http.Response {
	h := http.Header{}
	if d.verdict != nil {
		relay(h, d.verdict.Header)
		h.Set("X-Tip-Proxy-Status", strconv.Itoa(d.verdict.Status))
		if line := d.verdict.Line(); line != "" {
			h.Set("X-Tip-Proxy-Error", singleLine.Replace(line))
		}
	}
	h.Set("X-Tip-Error", d.kind+": "+singleLine.Replace(d.message))
	return synthetic(req, http.StatusBadGateway, h)
}

// What a hop's refusal does not carry over: hop-by-hop fields, the description of the body TIP drops, and
// anything that would pass for TIP's own headers.
var unrelayed = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Connection": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true, "Content-Length": true, "Content-Encoding": true, "Content-Type": true,
}

func relay(dst, src http.Header) {
	skip := map[string]bool{}
	for _, v := range src.Values("Connection") {
		for name := range strings.SplitSeq(v, ",") {
			skip[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	for name, values := range src {
		if unrelayed[name] || skip[name] || strings.HasPrefix(name, directive.Prefix) {
			continue
		}
		dst[name] = slices.Clone(values)
	}
}

func unavailable(req *http.Request) *http.Response {
	h := http.Header{}
	h.Set("X-Tip-Error", "shutting down")
	h.Set("Connection", "close")
	return synthetic(req, http.StatusServiceUnavailable, h)
}

func synthetic(req *http.Request, status int, h http.Header) *http.Response {
	h.Set("Content-Length", "0")
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          http.NoBody,
		ContentLength: 0,
		Request:       req,
	}
}
