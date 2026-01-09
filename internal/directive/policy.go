package directive

import (
	"fmt"
	"net/http"
	"strings"
)

type Policy struct {
	defaults map[string]any
	deny     map[string]struct{}
}

func NewPolicy(defaults, deny []string) (Policy, error) {
	p := Policy{defaults: map[string]any{}, deny: map[string]struct{}{}}
	for _, name := range deny {
		key := strings.ToLower(strings.TrimSpace(name))
		if hasPrefix(key) {
			key = key[len(Prefix):]
		}
		if !isKnown(key) {
			return Policy{}, fmt.Errorf("deny: unknown directive %q", name)
		}
		p.deny[key] = struct{}{}
	}
	h := http.Header{}
	for _, line := range defaults {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return Policy{}, fmt.Errorf("defaults: %q is not a header line", line)
		}
		name = strings.TrimSpace(name)
		if !hasPrefix(name) {
			name = Prefix + name
		}
		h.Add(name, strings.TrimSpace(value))
	}
	if _, issues := Parse(h, Policy{defaults: map[string]any{}, deny: map[string]struct{}{}}); len(issues) > 0 {
		return Policy{}, fmt.Errorf("defaults: %w", issues)
	}
	for name, values := range h {
		key := strings.ToLower(name[len(Prefix):])
		shaped, _ := shapeValue(key, values)
		p.defaults[key] = shaped
	}
	return p, nil
}

func (p Policy) denied(key string) bool {
	_, ok := p.deny[key]
	return ok
}
