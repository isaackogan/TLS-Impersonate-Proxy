package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	z "github.com/Oudwins/zog"
	"github.com/Oudwins/zog/conf"
	"github.com/Oudwins/zog/parsers/zjson"
	"github.com/Oudwins/zog/zconst"
	"go.yaml.in/yaml/v3"
)

type InvalidError struct {
	Issues z.ZogIssueList
}

func (e InvalidError) Error() string {
	lines := make([]string, 0, len(e.Issues))
	for _, issue := range e.Issues {
		path := z.Issues.FlattenPath(issue.Path)
		if path == "" {
			path = "config"
		}
		lines = append(lines, path+": "+issue.Message)
	}
	return strings.Join(lines, "\n")
}

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	doc := map[string]any{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	if unknown := unknownKeys(doc, reflect.TypeFor[Config](), ""); len(unknown) > 0 {
		return Config{}, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(unknown, ", "))
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	var cfg Config
	if issues := schema.Parse(zjson.Decode(bytes.NewReader(encoded)), &cfg, z.WithIssueFormatter(formatIssue)); len(issues) > 0 {
		return Config{}, InvalidError{issues}
	}
	if cfg.Logging.Redact == nil {
		cfg.Logging.Redact = defaultRedact
	}
	return cfg, nil
}

func formatIssue(e *z.ZogIssue, ctx z.Ctx) {
	conf.DefaultIssueFormatter(e, ctx)
	if e.Code == zconst.IssueCodeCoerce && e.Err != nil {
		e.SetMessage(e.Err.Error())
	}
}

func Permissive(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Mode().Perm()&0o077 != 0, nil
}
