package directive

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/textproto"
	"strings"

	z "github.com/Oudwins/zog"
	"github.com/Oudwins/zog/conf"
	"github.com/Oudwins/zog/zconst"
)

type valueShape int

const (
	shapeScalar valueShape = iota
	shapeList
	shapeKV
)

var shapes = map[string]valueShape{"browser": shapeList, "os": shapeList, "keep": shapeList, "http2settings": shapeKV, "http3settings": shapeKV}

func hasPrefix(name string) bool {
	return len(name) >= len(Prefix) && strings.EqualFold(name[:len(Prefix)], Prefix)
}

func Parse(h http.Header, p Policy) (Directive, Issues) {
	req := make(map[string]any, len(h))
	var issues Issues
	for name, values := range h {
		if !hasPrefix(name) {
			continue
		}
		key := strings.ToLower(name[len(Prefix):])
		switch {
		case !isKnown(key):
			issues = append(issues, Issue{Path: name, Message: "unknown directive"})
		case p.denied(key):
			issues = append(issues, Issue{Path: officialName(key), Message: "not permitted by this proxy"})
		default:
			shaped, err := shapeValue(key, values)
			if err != nil {
				issues = append(issues, Issue{Path: officialName(key), Message: err.Error()})
				continue
			}
			req[key] = shaped
		}
	}
	in := make(map[string]any, len(p.defaults)+len(req))
	for key, value := range p.defaults {
		if !displaced(req, key) {
			in[key] = value
		}
	}
	maps.Copy(in, req)
	var d Directive
	issues = append(issues, fromZog(schema.Parse(in, &d, z.WithIssueFormatter(formatIssue)))...)
	if len(issues) > 0 {
		return Directive{}, issues
	}
	if d.Proxy == "" && p.requireProxy {
		issues = append(issues, Issue{Path: "Proxy", Message: "required by this proxy"})
	}
	if d.Proxy != "" && !p.proxyAllowed(d.Proxy) {
		issues = append(issues, Issue{Path: "Proxy", Message: p.hostMessage()})
	}
	if len(issues) > 0 {
		return Directive{}, issues
	}
	d.fromRequest = make(map[string]struct{}, len(req))
	for key := range req {
		d.fromRequest[key] = struct{}{}
	}
	return d, nil
}

// A default is displaced by the request naming the same directive, or one from the other identity group:
// Profile and the Browser, Os, Match trio are exclusive, so a request choosing one side drops defaults on the other.
func displaced(req map[string]any, key string) bool {
	if _, ok := req[key]; ok {
		return true
	}
	switch key {
	case "browser", "os", "match":
		_, ok := req["profile"]
		return ok
	case "profile":
		for _, other := range []string{"browser", "os", "match"} {
			if _, ok := req[other]; ok {
				return true
			}
		}
	}
	return false
}

func Strip(h http.Header) {
	for name := range h {
		if hasPrefix(name) {
			delete(h, name)
		}
	}
}

func shapeValue(key string, values []string) (any, error) {
	switch shapes[key] {
	case shapeList:
		raw := strings.Join(values, ",")
		if strings.TrimSpace(raw) == "" {
			return nil, errors.New("must not be empty")
		}
		return splitList(raw), nil
	case shapeKV:
		return parsePairs(key, strings.Join(values, ";"))
	}
	if len(values) > 1 {
		return nil, errors.New("sent more than once")
	}
	if strings.TrimSpace(values[0]) == "" {
		return nil, errors.New("must not be empty")
	}
	return values[0], nil
}

func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.ToLower(textproto.TrimString(part)))
	}
	return out
}

func parsePairs(key, raw string) (map[string]any, error) {
	pairs, err := http.ParseCookie(raw)
	if err != nil {
		return nil, fmt.Errorf("must be Key=Value pairs separated by semicolons: %w", err)
	}
	allowed := kvKeys[key]
	out := make(map[string]any, len(pairs)+1)
	order := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		name := strings.ToLower(pair.Name)
		if _, ok := allowed[name]; !ok {
			return nil, fmt.Errorf("unknown key %s", pair.Name)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%s given more than once", officialName(name))
		}
		out[name] = pair.Value
		order = append(order, name)
	}
	out["order"] = order
	return out, nil
}

func formatIssue(e *z.ZogIssue, ctx z.Ctx) {
	conf.DefaultIssueFormatter(e, ctx)
	if e.Code == zconst.IssueCodeCoerce && e.Err != nil {
		e.SetMessage(e.Err.Error())
	}
}

func fromZog(list z.ZogIssueList) Issues {
	if len(list) == 0 {
		return nil
	}
	out := make(Issues, 0, len(list))
	for _, issue := range list {
		out = append(out, Issue{Path: renderPath(issue.Path), Message: issue.Message})
	}
	return out
}

func renderPath(path []string) string {
	var b strings.Builder
	for _, segment := range path {
		if strings.HasPrefix(segment, "[") {
			b.WriteString(segment)
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(officialName(segment))
	}
	return b.String()
}
