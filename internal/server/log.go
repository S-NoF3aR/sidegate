// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"time"

	"sidegate/internal/session"
)

type logInfoKey struct{}

type logInfo struct{ user, app string }

func setLogUser(r *http.Request, sess *session.Session) {
	if sess != nil {
		setLogName(r, sess.Username)
	}
}

func setLogApp(r *http.Request, app string) {
	if li, ok := r.Context().Value(logInfoKey{}).(*logInfo); ok {
		li.app = app
	}
}

func setLogName(r *http.Request, name string) {
	if li, ok := r.Context().Value(logInfoKey{}).(*logInfo); ok {
		li.user = name
	}
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		li := &logInfo{}
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), logInfoKey{}, li)))
		s.metrics.observe(li.app, r.Method, rec.status, time.Since(start))
		s.log.Info("request",
			"host", r.Host,
			"app", li.app,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"bytes", rec.bytes,
			"user", li.user,
			"remote", r.RemoteAddr,
			"duration", time.Since(start).Round(time.Microsecond),
		)
	})
}

// recorder captures the status code while still supporting the optional
// interfaces the reverse proxy needs for streaming and WebSockets.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *recorder) Flush() {
	http.NewResponseController(r.ResponseWriter).Flush()
}

func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.status = http.StatusSwitchingProtocols
	return http.NewResponseController(r.ResponseWriter).Hijack()
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
