package proxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

var singleLine = strings.NewReplacer("\r", " ", "\n", " ")

func teapot(req *http.Request, issues directive.Issues) *http.Response {
	return synthetic(req, http.StatusTeapot, issues.Headers())
}

func badGateway(req *http.Request, kind string, err error) *http.Response {
	h := http.Header{}
	h.Set("X-Tip-Error", kind+": "+singleLine.Replace(err.Error()))
	return synthetic(req, http.StatusBadGateway, h)
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
