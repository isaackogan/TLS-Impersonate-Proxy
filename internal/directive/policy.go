package directive

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type Policy struct {
	defaults     map[string]any
	deny         map[string]struct{}
	proxyHosts   []string
	requireProxy bool
}

func NewPolicy(defaults map[string]string, deny []string) (Policy, error) {
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
	for name, value := range defaults {
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

// ProxyHosts restricts the host of X-Tip-Proxy to the patterns given: a host, a host with a port, or a *.suffix
// wildcard, matched case-insensitively. An empty list allows any host. A configured default must pass too.
func (p Policy) ProxyHosts(patterns []string) (Policy, error) {
	p.proxyHosts = nil
	for _, raw := range patterns {
		pattern := strings.ToLower(strings.TrimSpace(raw))
		if pattern == "" || strings.ContainsAny(pattern, "/@ \t") {
			return Policy{}, fmt.Errorf("proxy_hosts: %q is not a host pattern", raw)
		}
		p.proxyHosts = append(p.proxyHosts, pattern)
	}
	if def, ok := p.defaults["proxy"].(string); ok && !p.proxyAllowed(def) {
		return Policy{}, errors.New("defaults: Proxy: " + p.hostMessage())
	}
	return p, nil
}

// RequireProxy makes a request that would leave without an upstream proxy, after defaults, a validation error.
func (p Policy) RequireProxy() (Policy, error) {
	if _, denied := p.deny["proxy"]; denied {
		if _, ok := p.defaults["proxy"]; !ok {
			return Policy{}, errors.New("require_proxy: Proxy is denied and has no default, so no request could pass")
		}
	}
	p.requireProxy = true
	return p, nil
}

func (p Policy) denied(key string) bool {
	_, ok := p.deny[key]
	return ok
}

func (p Policy) hostMessage() string {
	return "host must be one of " + strings.Join(p.proxyHosts, ", ")
}

func (p Policy) proxyAllowed(raw string) bool {
	if len(p.proxyHosts) == 0 {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	name := strings.ToLower(u.Hostname())
	for _, pattern := range p.proxyHosts {
		host, port := splitPattern(pattern)
		if port != "" && port != u.Port() {
			continue
		}
		if host == name || (strings.HasPrefix(host, "*.") && strings.HasSuffix(name, host[1:])) {
			return true
		}
	}
	return false
}

func splitPattern(pattern string) (host, port string) {
	if h, p, err := net.SplitHostPort(pattern); err == nil {
		return h, p
	}
	return strings.Trim(pattern, "[]"), ""
}
