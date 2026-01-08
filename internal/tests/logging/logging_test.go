package logging_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/logging"
)

func lastLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return lines[len(lines)-1]
}

func TestNewSelectsFormatAndLevel(t *testing.T) {
	cases := []struct {
		name, level, format string
		wantJSON            bool
		wantDebugLogged     bool
	}{
		{"json info", "info", "json", true, false},
		{"json debug", "debug", "json", true, true},
		{"text warn", "warn", "text", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log, err := logging.New(logging.Options{Level: tc.level, Format: tc.format}, &buf)
			if err != nil {
				t.Fatal(err)
			}
			log.Debug("probe")
			log.Error("boom", "k", "v")
			out := buf.String()
			if got := strings.Contains(out, "probe"); got != tc.wantDebugLogged {
				t.Fatalf("debug logged = %v, want %v", got, tc.wantDebugLogged)
			}
			if tc.wantJSON {
				var rec map[string]any
				if err := json.Unmarshal([]byte(lastLine(out)), &rec); err != nil {
					t.Fatalf("not json: %v\n%s", err, out)
				}
				if rec["msg"] != "boom" || rec["k"] != "v" {
					t.Fatalf("unexpected record %v", rec)
				}
			} else if !strings.Contains(out, "msg=boom") {
				t.Fatalf("not text: %s", out)
			}
		})
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	for _, o := range []logging.Options{{Level: "loud", Format: "json"}, {Level: "info", Format: "xml"}} {
		if _, err := logging.New(o, &bytes.Buffer{}); err == nil {
			t.Fatalf("expected error for %+v", o)
		}
	}
}

func TestRedactor(t *testing.T) {
	r := logging.NewRedactor([]string{"Authorization", "cookie"})
	if got := r.Value("authorization", "Bearer x"); got != logging.Redacted {
		t.Fatalf("got %q", got)
	}
	if got := r.Value("Cookie", "a=b"); got != logging.Redacted {
		t.Fatalf("got %q", got)
	}
	if got := r.Value("Accept", "*/*"); got != "*/*" {
		t.Fatalf("got %q", got)
	}
}
