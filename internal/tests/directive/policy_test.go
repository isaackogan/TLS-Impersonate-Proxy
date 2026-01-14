package directive_test

import (
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

func TestNewPolicyValidates(t *testing.T) {
	cases := []struct {
		name     string
		defaults map[string]string
		deny     []string
		wantErr  bool
	}{
		{"ok", map[string]string{"Browser": "Chrome", "X-Tip-Os": "IOS,Android"}, []string{"Proxy", "x-tip-dns"}, false},
		{"bad default value", map[string]string{"Browser": "Safari"}, nil, true},
		{"unknown default", map[string]string{"Colour": "red"}, nil, true},
		{"unknown deny", nil, []string{"Colour"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := directive.NewPolicy(tc.defaults, tc.deny)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
