package directive

import (
	"net/http"
	"strconv"
	"strings"
)

var singleLine = strings.NewReplacer("\r", " ", "\n", " ")

type Issue struct {
	Path    string
	Message string
}

func (i Issue) String() string {
	if i.Path == "" {
		return i.Message
	}
	return i.Path + ": " + i.Message
}

type Issues []Issue

func (is Issues) Error() string {
	parts := make([]string, len(is))
	for i, issue := range is {
		parts[i] = issue.String()
	}
	return strings.Join(parts, "; ")
}

func (is Issues) Headers() http.Header {
	h := http.Header{}
	h.Set("X-Tip-Error-Count", strconv.Itoa(len(is)))
	for _, issue := range is {
		h.Add("X-Tip-Error", singleLine.Replace(issue.String()))
	}
	return h
}
