package impersonate

import (
	"strings"

	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome"
	"github.com/enetx/surf/profiles/firefox"
)

type Inference struct {
	Browser string
	Os      string
}

var osNames = map[profiles.OSKey]string{
	profiles.Windows: "windows", profiles.MacOS: "macos", profiles.Linux: "linux", profiles.Android: "android", profiles.IOS: "ios",
}

func Infer(userAgent string) Inference {
	for key, ua := range chrome.UserAgent {
		if ua.Std() == userAgent {
			return Inference{"chrome", osNames[key]}
		}
	}
	for key, ua := range firefox.UserAgent {
		if ua.Std() == userAgent {
			return Inference{"firefox", osNames[key]}
		}
	}
	var browser string
	switch {
	case strings.Contains(userAgent, "Firefox/") || strings.Contains(userAgent, "FxiOS/"):
		browser = "firefox"
	case strings.Contains(userAgent, "Chrome/") || strings.Contains(userAgent, "CriOS/") || strings.Contains(userAgent, "Chromium/"):
		browser = "chrome"
	default:
		return Inference{}
	}
	return Inference{browser, platform(userAgent)}
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
