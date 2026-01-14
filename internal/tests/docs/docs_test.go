package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

var (
	root        = filepath.Join("..", "..", "..")
	examplesDir = filepath.Join(root, "docs", "examples")
	namePattern = regexp.MustCompile(`^(ca|plain)-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.[a-z]+$`)
	snippet     = regexp.MustCompile("(?s)<!-- example: ([^ ]+) -->\n```[a-z]*\n(.*?)```")
	link        = regexp.MustCompile(`\]\((?:\./)?(?:docs/)?examples/([^)]+)\)`)
)

func examples(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(examplesDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestExampleNamesFollowTheScheme(t *testing.T) {
	for _, name := range examples(t) {
		if !namePattern.MatchString(name) {
			t.Errorf("%s does not match <mode>-<language>-<library>-<scenario>.<ext>", name)
		}
	}
}

func TestEveryExampleIsLinkedFromDocsReadme(t *testing.T) {
	doc := read(t, filepath.Join(root, "docs", "README.md"))
	linked := map[string]bool{}
	for _, m := range link.FindAllStringSubmatch(doc, -1) {
		linked[m[1]] = true
		if _, err := os.Stat(filepath.Join(examplesDir, m[1])); err != nil {
			t.Errorf("docs/README.md links missing example %s", m[1])
		}
	}
	for _, name := range examples(t) {
		if !linked[name] {
			t.Errorf("%s is not linked from docs/README.md", name)
		}
	}
}

func TestRootReadmeLinksResolve(t *testing.T) {
	doc := read(t, filepath.Join(root, "README.md"))
	for _, m := range link.FindAllStringSubmatch(doc, -1) {
		if _, err := os.Stat(filepath.Join(examplesDir, m[1])); err != nil {
			t.Errorf("README.md links missing example %s", m[1])
		}
	}
}

func TestSnippetsEqualExamples(t *testing.T) {
	for _, path := range []string{filepath.Join(root, "README.md"), filepath.Join(root, "docs", "README.md")} {
		doc := read(t, path)
		matches := snippet.FindAllStringSubmatch(doc, -1)
		if len(matches) == 0 {
			t.Errorf("%s has no marked snippets", path)
		}
		for _, m := range matches {
			want := read(t, filepath.Join(examplesDir, m[1]))
			if strings.TrimSpace(m[2]) != strings.TrimSpace(want) {
				t.Errorf("%s: snippet %s drifted from the example file", path, m[1])
			}
		}
	}
}

func TestExamplesUseOnlyKnownDirectives(t *testing.T) {
	known := map[string]bool{"error": true, "errorcount": true}
	for _, name := range directive.Names() {
		known[strings.ToLower(name)] = true
	}
	pattern := regexp.MustCompile(`X-Tip-([A-Za-z0-9]+)`)
	for _, name := range examples(t) {
		content := read(t, filepath.Join(examplesDir, name))
		for _, m := range pattern.FindAllStringSubmatch(content, -1) {
			if !known[strings.ToLower(m[1])] {
				t.Errorf("%s uses unknown directive X-Tip-%s", name, m[1])
			}
		}
	}
	for _, path := range []string{filepath.Join(root, "README.md"), filepath.Join(root, "docs", "README.md")} {
		for _, m := range pattern.FindAllStringSubmatch(read(t, path), -1) {
			if !known[strings.ToLower(m[1])] {
				t.Errorf("%s mentions unknown directive X-Tip-%s", path, m[1])
			}
		}
	}
}
