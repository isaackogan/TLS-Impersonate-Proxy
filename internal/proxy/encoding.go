package proxy

import (
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func acceptEncodings(values []string) []string {
	var out []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			token, _, _ := strings.Cut(part, ";")
			if token = strings.ToLower(strings.TrimSpace(token)); token != "" {
				out = append(out, token)
			}
		}
	}
	return out
}

func negotiate(mode string, accept []string, resp *http.Response) error {
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if encoding == "" || encoding == "identity" || mode == "passthrough" {
		return nil
	}
	if mode == "negotiate" && (slices.Contains(accept, encoding) || slices.Contains(accept, "*")) {
		return nil
	}
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified || resp.ContentLength == 0 || (resp.Request != nil && resp.Request.Method == http.MethodHead) {
		return nil
	}
	body, err := decoder(encoding, resp.Body)
	if err != nil || body == nil {
		return err
	}
	resp.Body = body
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Uncompressed = true
	return nil
}

type decoded struct {
	io.ReadCloser
	source io.Closer
}

func (d *decoded) Close() error {
	d.ReadCloser.Close()
	return d.source.Close()
}

func decoder(encoding string, body io.ReadCloser) (io.ReadCloser, error) {
	switch encoding {
	case "gzip":
		r, err := gzip.NewReader(body)
		if err != nil {
			return nil, err
		}
		return &decoded{r, body}, nil
	case "deflate":
		r, err := zlib.NewReader(body)
		if err != nil {
			return nil, err
		}
		return &decoded{r, body}, nil
	case "br":
		return &decoded{io.NopCloser(brotli.NewReader(body)), body}, nil
	case "zstd":
		r, err := zstd.NewReader(body)
		if err != nil {
			return nil, err
		}
		return &decoded{r.IOReadCloser(), body}, nil
	}
	return nil, nil
}
