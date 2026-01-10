package metrics

import (
	"fmt"
	"slices"
	"strings"
)

type Route struct {
	Name    string
	Host    string
	Path    string
	Capture []string
}

type route struct {
	name     string
	host     string
	segments []string
	capture  map[string]bool
}

type Matcher struct {
	routes   []route
	captures []string
}

func NewMatcher(routes []Route) (*Matcher, error) {
	m := &Matcher{}
	seen := map[string]bool{}
	for _, r := range routes {
		segments := strings.Split(strings.TrimPrefix(r.Path, "/"), "/")
		params := map[string]bool{}
		for i, segment := range segments {
			if segment == "*" && i != len(segments)-1 {
				return nil, fmt.Errorf("route %s: * must be the last segment", r.Name)
			}
			if _, name, ok := strings.Cut(segment, ":"); ok {
				params[name] = true
			}
		}
		compiled := route{name: r.Name, host: strings.ToLower(r.Host), segments: segments, capture: map[string]bool{}}
		for _, name := range r.Capture {
			if !params[name] {
				return nil, fmt.Errorf("route %s: capture %q is not a parameter of %s", r.Name, name, r.Path)
			}
			compiled.capture[name] = true
			if !seen[name] {
				seen[name] = true
				m.captures = append(m.captures, name)
			}
		}
		m.routes = append(m.routes, compiled)
	}
	slices.Sort(m.captures)
	return m, nil
}

func (m *Matcher) Captures() []string { return m.captures }

func (m *Matcher) Match(host, path string) (string, map[string]string) {
	host = strings.ToLower(host)
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, r := range m.routes {
		if !matchHost(r.host, host) {
			continue
		}
		if labels, ok := matchPath(r, segments); ok {
			return r.name, labels
		}
	}
	return "", nil
}

func matchHost(pattern, host string) bool {
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suffix)
	}
	return pattern == host
}

func matchPath(r route, segments []string) (map[string]string, bool) {
	labels := map[string]string{}
	for i, pattern := range r.segments {
		if pattern == "*" {
			return labels, true
		}
		if i >= len(segments) || segments[i] == "" {
			return nil, false
		}
		if prefix, name, ok := strings.Cut(pattern, ":"); ok {
			value, hasPrefix := strings.CutPrefix(segments[i], prefix)
			if !hasPrefix || value == "" {
				return nil, false
			}
			if r.capture[name] {
				labels[name] = value
			}
			continue
		}
		if pattern != segments[i] {
			return nil, false
		}
	}
	return labels, len(segments) == len(r.segments)
}
