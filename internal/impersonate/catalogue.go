package impersonate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/enetx/http2"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome"
)

type Profile struct {
	ID              string `json:"id"`
	Browser         string `json:"browser"`
	Os              string `json:"os"`
	Mobile          bool   `json:"mobile"`
	Fidelity        string `json:"fidelity"`
	UserAgent       string `json:"userAgent"`
	SecChUa         string `json:"secChUa,omitempty"`
	SecChUaPlatform string `json:"secChUaPlatform,omitempty"`
	SecChUaMobile   string `json:"secChUaMobile,omitempty"`
	family          string
	platform        string
}

type Catalogue struct {
	Revision string    `json:"revision"`
	Profiles []Profile `json:"profiles"`
	byID     map[string]Profile
}

var (
	official = map[string]string{"chrome": "Chrome", "firefox": "Firefox", "edge": "Edge", "windows": "Windows", "macos": "MacOS", "linux": "Linux", "android": "Android", "ios": "IOS"}

	catalogueOnce sync.Once
	catalogue     Catalogue
)

func Profiles() Catalogue {
	catalogueOnce.Do(buildCatalogue)
	return catalogue
}

func (p Profile) Family() string   { return p.family }
func (p Profile) Platform() string { return p.platform }

func Lookup(id string) (Profile, bool) {
	p, ok := Profiles().byID[strings.ToLower(id)]
	return p, ok
}

func buildCatalogue() {
	c := Catalogue{byID: map[string]Profile{}}
	revision := sha256.New()
	for _, name := range Families() {
		f := families[name]
		for _, os := range f.oses {
			p := profileFor(f, os)
			c.Profiles = append(c.Profiles, p)
			c.byID[p.ID] = p
			revision.Write([]byte(p.ID))
		}
	}
	c.Revision = hex.EncodeToString(revision.Sum(nil))[:12]
	catalogue = c
}

func profileFor(f *family, os string) Profile {
	key := osKeys[os]
	p := Profile{
		Browser:   official[f.name],
		Os:        official[os],
		Mobile:    key.IsMobile(),
		Fidelity:  "high",
		UserAgent: f.agent(os),
		family:    f.name,
		platform:  os,
	}
	if os == "ios" {
		p.Fidelity = "low"
	}
	if f.hints {
		p.SecChUa = chrome.SecCHUA
		if f.headers != nil {
			p.SecChUa = f.headers(os)["sec-ch-ua"]
		}
		p.SecChUaPlatform = chrome.Platform.Get(key).UnwrapOrDefault().Std()
		p.SecChUaMobile = key.Mobile().Std()
	}
	identity := strings.Join([]string{f.name, os, p.UserAgent, p.SecChUa, p.SecChUaPlatform, p.SecChUaMobile, fingerprintDigest(f.variant(key.IsMobile()))}, "\n")
	sum := sha256.Sum256([]byte(identity))
	p.ID = hex.EncodeToString(sum[:])[:12]
	return p
}

func fingerprintDigest(v profiles.Variant) string {
	var b strings.Builder
	if v.HelloSpec != nil {
		for _, suite := range v.HelloSpec.CipherSuites {
			fmt.Fprintf(&b, "%d,", suite)
		}
		for _, ext := range v.HelloSpec.Extensions {
			fmt.Fprintf(&b, "%T;", ext)
		}
	} else {
		b.WriteString(v.HelloID.Str())
	}
	rec := &h2recorder{}
	v.ConfigureH2(rec)
	b.WriteString(rec.String())
	return b.String()
}

type h2recorder struct{ parts []string }

func (r *h2recorder) add(name string, v any) profiles.H2Config {
	r.parts = append(r.parts, fmt.Sprintf("%s=%v", name, v))
	return r
}

func (r *h2recorder) String() string { return strings.Join(r.parts, ";") }

func (r *h2recorder) HeaderTableSize(v uint32) profiles.H2Config      { return r.add("hts", v) }
func (r *h2recorder) EnablePush(v uint32) profiles.H2Config           { return r.add("push", v) }
func (r *h2recorder) MaxConcurrentStreams(v uint32) profiles.H2Config { return r.add("mcs", v) }
func (r *h2recorder) InitialWindowSize(v uint32) profiles.H2Config    { return r.add("iws", v) }
func (r *h2recorder) MaxFrameSize(v uint32) profiles.H2Config         { return r.add("mfs", v) }
func (r *h2recorder) MaxHeaderListSize(v uint32) profiles.H2Config    { return r.add("mhls", v) }
func (r *h2recorder) NoRFC7540Priorities(v uint32) profiles.H2Config  { return r.add("norfc", v) }
func (r *h2recorder) ConnectionFlow(v uint32) profiles.H2Config       { return r.add("flow", v) }
func (r *h2recorder) InitialStreamID(v uint32) profiles.H2Config      { return r.add("sid", v) }
func (r *h2recorder) PriorityParam(v http2.PriorityParam) profiles.H2Config {
	return r.add("prio", v)
}
func (r *h2recorder) PriorityFrames(v []http2.PriorityFrame) profiles.H2Config {
	return r.add("frames", v)
}
