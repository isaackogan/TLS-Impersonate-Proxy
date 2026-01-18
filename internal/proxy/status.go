package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"

	"github.com/isaackogan/tls-impersonate-proxy/internal/connect"
)

// proxyStatus is TIP's entry in an RFC 9209 Proxy-Status field.
type proxyStatus struct {
	err      string
	nextHop  string
	received int
	details  string
}

func (p proxyStatus) String() string {
	var b strings.Builder
	b.WriteString("tip")
	if p.err != "" {
		b.WriteString("; error=" + p.err)
	}
	if p.nextHop != "" {
		b.WriteString("; next-hop=" + sfString(p.nextHop))
	}
	if p.received != 0 {
		fmt.Fprintf(&b, "; received-status=%d", p.received)
	}
	if p.details != "" {
		b.WriteString("; details=" + sfString(p.details))
	}
	return b.String()
}

// sfString quotes a Structured Field string: printable ASCII with backslash and quote escaped.
func sfString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r > 0x7e:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// errorType maps a diagnosed failure onto an RFC 9209 error type.
func errorType(d diagnosis, err error) string {
	switch d.kind {
	case "timeout":
		if d.phase != "" || !d.connected {
			return "connection_timeout"
		}
		return "http_response_timeout"
	case "proxy_rejected":
		return "http_request_error"
	case "tls":
		return tlsErrorType(err)
	case "dial", "proxy":
		if d.phase == connect.PhaseTLS {
			return tlsErrorType(err)
		}
		return dialErrorType(err)
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "http_response_incomplete"
	}
	return "connection_terminated"
}

func dialErrorType(err error) string {
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns):
		return "dns_error"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "destination_ip_unroutable"
	}
	return "destination_unavailable"
}

func tlsErrorType(err error) string {
	var verification *tls.CertificateVerificationError
	var alert tls.AlertError
	msg := strings.ToLower(err.Error())
	switch {
	case errors.As(err, &verification), strings.Contains(msg, "certificate"):
		return "tls_certificate_error"
	case errors.As(err, &alert), strings.Contains(msg, "alert"):
		return "tls_alert_received"
	}
	return "tls_protocol_error"
}
