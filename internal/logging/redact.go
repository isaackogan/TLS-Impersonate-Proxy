package logging

import "regexp"

import "strings"

const Redacted = "[redacted]"

type Redactor map[string]struct{}

func NewRedactor(names []string) Redactor {
	r := make(Redactor, len(names))
	for _, name := range names {
		r[strings.ToLower(name)] = struct{}{}
	}
	return r
}

func (r Redactor) Value(name, value string) string {
	if _, hidden := r[strings.ToLower(name)]; hidden {
		return Redacted
	}
	return value
}

// userinfo matches the credentials of any URL inside free text, up to the last @ before a slash or a space,
// so a password containing @ is covered whole.
var userinfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.\-]*://)[^/\s]*@`)

// RedactUserinfo replaces the credentials of every URL in s with ***. It is applied where TIP renders text it
// did not write itself: upstream errors, a hop's body, build failures.
func RedactUserinfo(s string) string {
	return userinfo.ReplaceAllString(s, "${1}***@")
}
