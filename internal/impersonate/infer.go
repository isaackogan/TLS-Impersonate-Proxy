package impersonate

import "strings"

type Inference struct {
	Browser string
	Os      string
}

func Infer(userAgent string) Inference {
	for _, name := range detectionOrder {
		f := families[name]
		for _, os := range f.oses {
			if f.agent(os) == userAgent {
				return Inference{name, os}
			}
		}
	}
	for _, name := range detectionOrder {
		for _, marker := range families[name].detect {
			if strings.Contains(userAgent, marker) {
				return closest(name, platform(userAgent))
			}
		}
	}
	return Inference{}
}

func closest(browser, os string) Inference {
	if os != "" && !containsOs(browser, os) {
		return Inference{"chrome", os}
	}
	return Inference{browser, os}
}

func containsOs(browser, os string) bool {
	for _, candidate := range families[browser].oses {
		if candidate == os {
			return true
		}
	}
	return false
}

func platform(userAgent string) string {
	switch {
	case strings.Contains(userAgent, "Android"):
		return "android"
	case strings.Contains(userAgent, "iPhone") || strings.Contains(userAgent, "iPad") || strings.Contains(userAgent, "iPod"):
		return "ios"
	case strings.Contains(userAgent, "Windows"):
		return "windows"
	case strings.Contains(userAgent, "Macintosh") || strings.Contains(userAgent, "Mac OS X"):
		return "macos"
	case strings.Contains(userAgent, "Linux") || strings.Contains(userAgent, "X11"):
		return "linux"
	}
	return ""
}
