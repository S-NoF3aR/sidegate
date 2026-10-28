// SPDX-License-Identifier: AGPL-3.0-only

// Command sidegate-server is an identity-aware reverse proxy that authenticates
// users via OIDC and authorizes access to apps by group membership.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"sidegate/internal/config"
	"sidegate/internal/recording"
	"sidegate/internal/server"
	"sidegate/internal/store"
)

const defaultConfigPath = "/etc/sidegate/config.yaml"

// shutdownDelay is how long the server keeps serving after SIGTERM with
// readiness failing, so no new requests arrive once it stops.
const shutdownDelay = 5 * time.Second

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	configPath := flag.String("config", os.Getenv("SIDEGATE_CONFIG"),
		"path to an optional config file (default "+defaultConfigPath+" if it exists); SIDEGATE_* variables override it")
	healthcheck := flag.Bool("healthcheck", false, "probe the readiness endpoint of a running instance and exit (for Docker HEALTHCHECK)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	server.Version = version
	server.Register(recording.New())
	if *showVersion {
		fmt.Printf("Sidegate %s\n", version)
		return
	}
	if *configPath == "" {
		if _, err := os.Stat(defaultConfigPath); err == nil {
			*configPath = defaultConfigPath
		}
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("invalid config", "path", *configPath, "error", err)
		os.Exit(1)
	}
	if *healthcheck {
		os.Exit(probe(cfg.HealthListen))
	}
	log := newLogger(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var ready atomic.Bool
	var metrics atomic.Pointer[http.Handler]
	health := &http.Server{Addr: cfg.HealthListen, Handler: healthHandler(&ready, &metrics), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := health.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("health listener failed", "error", err)
			os.Exit(1)
		}
	}()

	st, err := retry(ctx, log, "database", func() (*store.Store, error) {
		return store.Open(ctx, cfg.Database.URL)
	})
	if err != nil {
		log.Error("startup aborted", "error", err)
		os.Exit(1)
	}
	defer st.Close()
	if err := seed(ctx, cfg, st, log); err != nil {
		log.Error("seeding database failed", "error", err)
		os.Exit(1)
	}

	// This context lives as long as the server; it is used for refreshing
	// the provider's signing keys.
	oidcCtx := oidc.ClientContext(context.Background(), &http.Client{Timeout: 15 * time.Second})
	srv, err := retry(ctx, log, "server init", func() (*server.Server, error) {
		return server.New(oidcCtx, cfg, st, log)
	})
	if err != nil {
		log.Error("startup aborted", "error", err)
		os.Exit(1)
	}
	mh := srv.MetricsHandler()
	metrics.Store(&mh)
	go srv.Watch(ctx, 5*time.Second)
	go func() {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		for range hup {
			if err := srv.Sync(ctx); err != nil {
				log.Warn("sync from database", "error", err)
			}
		}
	}()

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No read/write timeouts: they would cut off WebSockets and
		// long-running downloads of proxied apps.
	}
	go func() {
		log.Info("listening", "version", version, "addr", cfg.Listen, "portal", cfg.PublicURL, "domain", cfg.Domain)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listener failed", "error", err)
			os.Exit(1)
		}
	}()
	ready.Store(true)

	<-ctx.Done()
	log.Info("shutting down")
	// Fail readiness first and keep serving for a moment, until load
	// balancers and Kubernetes endpoints stop sending new requests here.
	ready.Store(false)
	time.Sleep(shutdownDelay)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Open RDP/SSH connections get a "restarting" message instead of just
	// dropping; then running requests finish.
	srv.Drain(shutdownCtx)
	httpSrv.Shutdown(shutdownCtx)
	health.Shutdown(shutdownCtx)
}

// retry calls fn until it succeeds, so the proxy survives starting before
// the database or the identity provider is reachable.
func retry[T any](ctx context.Context, log *slog.Logger, what string, fn func() (T, error)) (T, error) {
	backoff := time.Second
	for {
		v, err := fn()
		if err == nil {
			return v, nil
		}
		log.Warn(what+" failed, retrying", "error", err, "in", backoff)
		select {
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// seed imports apps and groups from the config file into an empty
// database, which migrates file based setups.
func seed(ctx context.Context, cfg *config.Config, st *store.Store, log *slog.Logger) error {
	if len(cfg.Apps) == 0 && len(cfg.Groups) == 0 {
		return nil
	}
	seeded, err := st.SeedFromConfig(ctx, cfg)
	if err != nil {
		return err
	}
	if seeded {
		log.Info("imported apps and groups from the config file into the database", "apps", len(cfg.Apps), "groups", len(cfg.Groups))
	} else {
		log.Info("database already has apps; apps and groups in the config file are ignored")
	}
	return nil
}

// healthHandler serves probes and, once the server is up, Prometheus
// metrics on the internal health port.
func healthHandler(ready *atomic.Bool, metrics *atomic.Pointer[http.Handler]) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		h := metrics.Load()
		if h == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		(*h).ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	return mux
}

func probe(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/readyz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
	slog.SetDefault(log)
	return log
}
