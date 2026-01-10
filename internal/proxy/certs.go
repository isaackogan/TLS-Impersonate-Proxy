package proxy

import (
	"crypto/tls"
	"sync"
)

type certStore struct {
	mu    sync.Mutex
	max   int
	certs map[string]*tls.Certificate
}

func newCertStore(max int) *certStore {
	return &certStore{max: max, certs: make(map[string]*tls.Certificate, max)}
}

func (s *certStore) Fetch(host string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	s.mu.Lock()
	cert, ok := s.certs[host]
	s.mu.Unlock()
	if ok {
		return cert, nil
	}
	cert, err := gen()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if len(s.certs) >= s.max {
		for victim := range s.certs {
			delete(s.certs, victim)
			break
		}
	}
	s.certs[host] = cert
	s.mu.Unlock()
	return cert, nil
}
