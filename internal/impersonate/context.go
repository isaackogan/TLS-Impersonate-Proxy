package impersonate

import (
	"context"
	"net/http"
	"net/textproto"
	"slices"
	"strings"

	ehttp "github.com/enetx/http"
	"github.com/enetx/surf"
)

type keepKey struct{}

type captureKey struct{}

type keep struct {
	original http.Header
	names    []string
}

type Capture struct {
	Headers []string
}

func WithKeep(ctx context.Context, original http.Header, names []string) context.Context {
	return context.WithValue(ctx, keepKey{}, keep{original, names})
}

func WithCapture(ctx context.Context, c *Capture) context.Context {
	return context.WithValue(ctx, captureKey{}, c)
}

func finalize(req *surf.Request) error {
	r := req.GetRequest()
	ctx := r.Context()
	if k, ok := ctx.Value(keepKey{}).(keep); ok {
		for _, name := range k.names {
			r.Header.Del(name)
			for _, value := range k.original.Values(name) {
				r.Header.Add(name, value)
			}
		}
	}
	if c, ok := ctx.Value(captureKey{}).(*Capture); ok {
		c.Headers = lines(r.Header)
	}
	return nil
}

func lines(h ehttp.Header) []string {
	seen := map[string]bool{ehttp.HeaderOrderKey: true, ehttp.PHeaderOrderKey: true}
	var out []string
	emit := func(name string) {
		key := textproto.CanonicalMIMEHeaderKey(name)
		if seen[key] {
			return
		}
		seen[key] = true
		for _, value := range h[key] {
			out = append(out, strings.ToLower(key)+": "+value)
		}
	}
	for _, name := range h[ehttp.HeaderOrderKey] {
		emit(name)
	}
	rest := make([]string, 0, len(h))
	for key := range h {
		if !seen[key] {
			rest = append(rest, key)
		}
	}
	slices.Sort(rest)
	for _, key := range rest {
		emit(key)
	}
	return out
}
