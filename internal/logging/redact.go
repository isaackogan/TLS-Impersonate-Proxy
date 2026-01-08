package logging

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
