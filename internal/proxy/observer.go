package proxy

import "time"

type RequestEvent struct {
	Host     string
	Method   string
	Path     string
	Browser  string
	Route    string
	Status   int
	Duration time.Duration
	BytesIn  int64
	BytesOut int64
}

type Observer interface {
	RequestStarted()
	RequestFinished(RequestEvent)
	ValidationFailed(directive string)
	UpstreamError(host, kind string)
	TunnelOpened()
	Route(host, path string) string
}

type NopObserver struct{}

func (NopObserver) RequestStarted()              {}
func (NopObserver) RequestFinished(RequestEvent) {}
func (NopObserver) ValidationFailed(string)      {}
func (NopObserver) UpstreamError(string, string) {}
func (NopObserver) TunnelOpened()                {}
func (NopObserver) Route(string, string) string  { return "" }
