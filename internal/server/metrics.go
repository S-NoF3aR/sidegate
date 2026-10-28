// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// App labels for requests that don't belong to an app.
const (
	appPortal  = "_portal"
	appUnknown = "_unknown"
)

type metrics struct {
	reg            *prometheus.Registry
	requests       *prometheus.CounterVec
	duration       *prometheus.HistogramVec
	upstreamErrors *prometheus.CounterVec
	denied         *prometheus.CounterVec
	logins         *prometheus.CounterVec
	refreshes      *prometheus.CounterVec
	revoked        prometheus.Counter
	apps           prometheus.Gauge
	revision       prometheus.Gauge
	syncErrors     prometheus.Counter
	remoteSessions *prometheus.CounterVec
	remoteActive   *prometheus.GaugeVec
	eventsDropped  prometheus.Counter
}

func newMetrics() *metrics {
	reg := prometheus.NewRegistry()
	f := func(c prometheus.Collector) { reg.MustRegister(c) }
	m := &metrics{
		reg: reg,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sidegate_requests_total", Help: "HTTP requests by app, method and status code.",
		}, []string{"app", "method", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "sidegate_request_duration_seconds", Help: "Request duration by app, excluding WebSocket connections.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}, []string{"app"}),
		upstreamErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sidegate_upstream_errors_total", Help: "Requests that failed because the upstream was unreachable or broke the connection.",
		}, []string{"app"}),
		denied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sidegate_access_denied_total", Help: "Requests not proxied, by app and reason (unauthenticated, forbidden, step_up).",
		}, []string{"app", "reason"}),
		logins: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sidegate_logins_total", Help: "Completed sign-ins by result (success, failure).",
		}, []string{"result"}),
		refreshes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sidegate_session_refreshes_total", Help: "Session revalidations with the IdP by result (success, revoked, error).",
		}, []string{"result"}),
		revoked: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sidegate_revoked_sessions_rejected_total", Help: "Requests carrying a session an admin revoked.",
		}),
		apps: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sidegate_apps", Help: "Number of configured apps.",
		}),
		revision: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sidegate_config_revision", Help: "Database revision currently loaded; differs between replicas while they sync.",
		}),
		syncErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sidegate_database_sync_errors_total", Help: "Failed attempts to load changes from the database.",
		}),
	}
	f(m.requests)
	f(m.duration)
	f(m.upstreamErrors)
	f(m.denied)
	f(m.logins)
	f(m.refreshes)
	f(m.revoked)
	f(m.apps)
	f(m.revision)
	m.remoteSessions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sidegate_remote_sessions_total", Help: "RDP and SSH connections by app, protocol and client (browser, native).",
	}, []string{"app", "protocol", "client"})
	m.remoteActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sidegate_remote_sessions_active", Help: "Open RDP and SSH connections by app, protocol and client.",
	}, []string{"app", "protocol", "client"})
	f(m.syncErrors)
	f(m.remoteSessions)
	f(m.remoteActive)
	m.eventsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sidegate_extension_events_dropped_total", Help: "Events not delivered to an extension because it fell behind.",
	})
	f(m.eventsDropped)
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sidegate_build_info", Help: "Version of the running proxy (always 1).",
	}, []string{"version"})
	buildInfo.WithLabelValues(Version).Set(1)
	f(buildInfo)
	f(collectors.NewGoCollector())
	f(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// MetricsHandler serves Prometheus metrics. Expose it on an internal port
// only.
func (s *Server) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(s.metrics.reg, promhttp.HandlerOpts{})
}

func (m *metrics) observe(app, method string, status int, d time.Duration) {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions:
	default:
		method = "OTHER" // keep label cardinality bounded
	}
	m.requests.WithLabelValues(app, method, strconv.Itoa(status)).Inc()
	if status != http.StatusSwitchingProtocols {
		m.duration.WithLabelValues(app).Observe(d.Seconds())
	}
}
