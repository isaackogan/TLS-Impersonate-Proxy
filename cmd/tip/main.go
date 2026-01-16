package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/netutil"

	"github.com/isaackogan/tls-impersonate-proxy/internal/config"
	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
	"github.com/isaackogan/tls-impersonate-proxy/internal/logging"
	"github.com/isaackogan/tls-impersonate-proxy/internal/metrics"
	"github.com/isaackogan/tls-impersonate-proxy/internal/proxy"
)

func main() {
	path := flag.String("config", "tip.yaml", "configuration file")
	flag.Parse()
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, "tip:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	log, err := logging.New(logging.Options{Level: cfg.Logging.Level, Format: cfg.Logging.Format}, os.Stdout)
	if err != nil {
		return err
	}
	log.Info("starting", "version", version, "config", path)
	if permissive, _ := config.Permissive(path); permissive && len(cfg.Auth.Users) > 0 {
		log.Warn("config file is readable by other users and contains credentials", "path", path)
	}
	ca, created, err := proxy.LoadOrCreateCA(cfg.Tls.CaCert, cfg.Tls.CaKey)
	if err != nil {
		return err
	}
	policy, err := directive.NewPolicy(cfg.Directives.Defaults, cfg.Directives.Deny)
	if err != nil {
		return err
	}
	var m *metrics.Metrics
	if cfg.Metrics.Enabled {
		if m, err = metrics.New(metrics.Options{Collectors: metrics.Collectors(cfg.Metrics.Collectors), Routes: routes(cfg.Metrics.Routes)}); err != nil {
			return err
		}
	}
	obs := observer{m}
	build := impersonate.Options{VerifyCertificates: cfg.Upstream.VerifyCertificates, ResponseHeaderTimeout: cfg.Upstream.Timeout}
	cache := impersonate.NewCache(impersonate.CacheOptions{Max: cfg.Clients.Max, IdleTtl: cfg.Clients.IdleTtl}, func(s directive.Spec) (*impersonate.Client, error) {
		return impersonate.Build(s, build)
	}, obs)
	defer cache.Close()
	srv, err := proxy.New(proxy.Options{
		CA:            ca,
		CertCacheSize: cfg.Tls.CertCacheSize,
		ClientHttp2:   cfg.Tls.ClientHttp2,
		Auth:          proxy.Auth{Realm: cfg.Auth.Realm, Users: cfg.Auth.Users},
		Encoding:      cfg.Encoding.Mode,
		Timeout:       cfg.Upstream.Timeout,
		ServeCa:       cfg.Server.ServeCa,
		ServeProfiles: cfg.Server.ServeProfiles,
		Redact:        logging.NewRedactor(cfg.Logging.Redact).Value,
	}, policy, clientSource{cache}, obs, log)
	if err != nil {
		return err
	}
	proxyListener, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return err
	}
	if cfg.Server.MaxConnections > 0 {
		proxyListener = netutil.LimitListener(proxyListener, cfg.Server.MaxConnections)
	}
	adminListener, err := net.Listen("tcp", cfg.Metrics.Listen)
	if err != nil {
		return err
	}
	log.Info("ca ready", "created", created, "fingerprint", proxy.Fingerprint(ca), "url", "http://"+proxyListener.Addr().String()+"/ca.pem")
	proxyServer := &http.Server{Handler: srv, ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout, IdleTimeout: cfg.Server.IdleTimeout, MaxHeaderBytes: cfg.Server.MaxHeaderBytes}
	admin := http.NewServeMux()
	admin.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	admin.Handle("/ca.pem", srv.CAHandler())
	admin.Handle("/profiles", srv.ProfilesHandler())
	if m != nil {
		admin.Handle(cfg.Metrics.Path, m.Handler())
	}
	adminServer := &http.Server{Handler: admin, ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout}
	failures := make(chan error, 2)
	go func() { failures <- proxyServer.Serve(proxyListener) }()
	go func() { failures <- adminServer.Serve(adminListener) }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go sweep(ctx, cache, cfg.Clients.IdleTtl/4)
	log.Info("ready", "version", version, "proxy", proxyListener.Addr().String(), "admin", adminListener.Addr().String())
	select {
	case <-ctx.Done():
	case err := <-failures:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	log.Info("shutting down", "grace", cfg.Server.ShutdownGrace.String())
	graceCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownGrace)
	defer cancel()
	proxyServer.Shutdown(graceCtx)
	if err := srv.Drain(graceCtx); err != nil {
		log.Warn("shutdown cut requests short", "error", err.Error())
	}
	adminServer.Shutdown(graceCtx)
	return nil
}

func sweep(ctx context.Context, cache *impersonate.Cache, every time.Duration) {
	ticker := time.NewTicker(max(every, time.Second))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			cache.Sweep(now)
		}
	}
}

func routes(list []config.Route) []metrics.Route {
	out := make([]metrics.Route, len(list))
	for i, r := range list {
		out[i] = metrics.Route{Name: r.Name, Host: r.Host, Path: r.Path, Capture: r.Capture}
	}
	return out
}
