package proxy

import (
	"bufio"
	"bytes"
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

func negotiate(mode string, accept []string, resp *http.Response) {
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if encoding == "" || encoding == "identity" || mode == "passthrough" {
		return
	}
	if mode == "negotiate" && (slices.Contains(accept, encoding) || slices.Contains(accept, "*")) {
		return
	}
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified || resp.ContentLength == 0 || (resp.Request != nil && resp.Request.Method == http.MethodHead) {
		return
	}
	body, decodable := decoder(encoding, resp.Body)
	resp.Body = body
	if !decodable {
		return
	}
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Uncompressed = true
}

type peeked struct {
	*bufio.Reader
	io.Closer
}

type decoded struct {
	io.ReadCloser
	source io.Closer
}

func (d *decoded) Close() error {
	d.ReadCloser.Close()
	return d.source.Close()
}

var (
	gzipMagic = []byte{0x1f, 0x8b}
	zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}
)

func decoder(encoding string, body io.ReadCloser) (io.ReadCloser, bool) {
	source := &peeked{bufio.NewReader(body), body}
	switch encoding {
	case "gzip":
		if !startsWith(source.Reader, gzipMagic) {
			return source, false
		}
		r, err := gzip.NewReader(source)
		if err != nil {
			return source, false
		}
		return &decoded{r, body}, true
	case "deflate":
		head, err := source.Peek(2)
		if err != nil || head[0]&0x0f != 8 || (uint16(head[0])<<8|uint16(head[1]))%31 != 0 {
			return source, false
		}
		r, err := zlib.NewReader(source)
		if err != nil {
			return source, false
		}
		return &decoded{r, body}, true
	case "br":
		return &decoded{io.NopCloser(brotli.NewReader(source)), body}, true
	case "zstd":
		if !startsWith(source.Reader, zstdMagic) {
			return source, false
		}
		r, err := zstd.NewReader(source)
		if err != nil {
			return source, false
		}
		return &decoded{r.IOReadCloser(), body}, true
	}
	return source, false
}

func startsWith(r *bufio.Reader, magic []byte) bool {
	head, err := r.Peek(len(magic))
	return err == nil && bytes.Equal(head, magic)
}
