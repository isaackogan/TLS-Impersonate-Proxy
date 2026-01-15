package impersonate

import (
	"regexp"
	"slices"
	"strings"

	"github.com/enetx/surf"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome"
	"github.com/enetx/surf/profiles/firefox"
)

type family struct {
	name    string
	oses    []string
	base    func(*surf.Impersonate) *surf.Builder
	variant func(mobile bool) profiles.Variant
	hints   bool
	agent   func(os string) string
	headers func(os string) map[string]string
	detect  []string
}

func chromeVariant(mobile bool) profiles.Variant {
	if mobile {
		return chrome.Mobile
	}
	return chrome.Desktop
}

func firefoxVariant(mobile bool) profiles.Variant {
	if mobile {
		return firefox.Mobile
	}
	return firefox.Desktop
}

var osKeys = map[string]profiles.OSKey{
	"windows": profiles.Windows, "macos": profiles.MacOS, "linux": profiles.Linux, "android": profiles.Android, "ios": profiles.IOS,
}

var osNames = map[profiles.OSKey]string{
	profiles.Windows: "windows", profiles.MacOS: "macos", profiles.Linux: "linux", profiles.Android: "android", profiles.IOS: "ios",
}

var allOses = []string{"windows", "macos", "linux", "android", "ios"}

var chromeMajor = regexp.MustCompile(`Chrome/(\d+)`)

func chromeAgent(os string) string  { return chrome.UserAgent.Get(osKeys[os]).UnwrapOrDefault().Std() }
func firefoxAgent(os string) string { return firefox.UserAgent.Get(osKeys[os]).UnwrapOrDefault().Std() }

func edgeAgent(os string) string {
	ua := chromeAgent(os)
	major := chromeMajor.FindStringSubmatch(ua)[1]
	if os == "android" {
		return ua + " EdgA/" + major + ".0.0.0"
	}
	return ua + " Edg/" + major + ".0.0.0"
}

func edgeHeaders(os string) map[string]string {
	return map[string]string{
		"User-Agent": edgeAgent(os),
		"sec-ch-ua":  strings.ReplaceAll(chrome.SecCHUA, `"Google Chrome"`, `"Microsoft Edge"`),
	}
}

var families = map[string]*family{
	"chrome": {
		name:    "chrome",
		oses:    allOses,
		base:    (*surf.Impersonate).Chrome,
		variant: chromeVariant,
		hints:   true,
		agent:   chromeAgent,
		detect:  []string{"Chrome/", "CriOS/", "Chromium/"},
	},
	"firefox": {
		name:    "firefox",
		oses:    allOses,
		base:    (*surf.Impersonate).Firefox,
		variant: firefoxVariant,
		agent:   firefoxAgent,
		detect:  []string{"Firefox/", "FxiOS/"},
	},
	"edge": {
		name:    "edge",
		oses:    []string{"windows", "macos", "linux", "android"},
		base:    (*surf.Impersonate).Chrome,
		variant: chromeVariant,
		hints:   true,
		agent:   edgeAgent,
		headers: edgeHeaders,
		detect:  []string{"Edg/", "EdgA/", "EdgiOS/"},
	},
}

var detectionOrder = []string{"edge", "firefox", "chrome"}

func Families() []string {
	names := make([]string, 0, len(families))
	for name := range families {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func OSes(browser string) []string {
	if f, ok := families[browser]; ok {
		return slices.Clone(f.oses)
	}
	return slices.Clone(allOses)
}

func UserAgent(browser, os string) (string, bool) {
	f, ok := families[browser]
	if !ok || !slices.Contains(f.oses, os) {
		return "", false
	}
	return f.agent(os), true
}
