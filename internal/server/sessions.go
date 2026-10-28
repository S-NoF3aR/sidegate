// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"sidegate/internal/session"
)

const (
	// Browsers drop cookies larger than ~4 KiB including name and
	// attributes, so larger sessions are split over numbered cookies.
	maxCookieValue = 3800
	maxChunks      = 4

	refreshTimeout = 15 * time.Second
)

// defaultRefreshResultTTL is how long a refresh result is reused for
// requests still carrying the old cookie (parallel asset loads) and how
// long a failing IdP is left alone.
const defaultRefreshResultTTL = 30 * time.Second

// errRevoked means the IdP refused the refresh token: the user was
// disabled, deleted, or their sessions were revoked.
var errRevoked = errors.New("session revoked by identity provider")

func (s *Server) chunkName(i int) string {
	if i == 0 {
		return s.cookieName
	}
	return s.cookieName + "_" + strconv.Itoa(i)
}

// loadSession returns the valid session of the request, or nil. It does not
// revalidate the session with the IdP; use authenticate for that.
func (s *Server) loadSession(r *http.Request) *session.Session {
	var val strings.Builder
	for i := range maxChunks {
		c, err := r.Cookie(s.chunkName(i))
		if err != nil {
			break
		}
		val.WriteString(c.Value)
	}
	if val.Len() == 0 {
		return nil
	}
	var sess session.Session
	if s.sessions.Open(s.cookieName, val.String(), &sess) != nil || !sess.Valid(time.Now()) {
		return nil
	}
	if s.revoked(&sess) {
		s.metrics.revoked.Inc()
		return nil
	}
	return &sess
}

func (s *Server) writeSession(w http.ResponseWriter, r *http.Request, sess *session.Session) error {
	val, err := s.sessions.Seal(s.cookieName, sess)
	if err != nil {
		return err
	}
	if len(val) > maxChunks*maxCookieValue {
		return fmt.Errorf("session is %d bytes, more than %d cookies can hold", len(val), maxChunks)
	}
	maxAge := int(time.Until(time.Unix(sess.Expiry, 0)).Seconds())
	i := 0
	for ; len(val) > 0; i++ {
		n := min(len(val), maxCookieValue)
		http.SetCookie(w, s.sessionCookie(s.chunkName(i), val[:n], maxAge))
		val = val[n:]
	}
	// Drop chunks left over from a larger previous session; they would
	// corrupt the concatenated value.
	for ; i < maxChunks; i++ {
		if _, err := r.Cookie(s.chunkName(i)); err == nil {
			http.SetCookie(w, s.sessionCookie(s.chunkName(i), "", -1))
		}
	}
	return nil
}

func (s *Server) clearSession(w http.ResponseWriter, r *http.Request) {
	for i := range maxChunks {
		if _, err := r.Cookie(s.chunkName(i)); err == nil || i == 0 {
			http.SetCookie(w, s.sessionCookie(s.chunkName(i), "", -1))
		}
	}
}

func (s *Server) sessionCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   s.domain,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// authenticate returns the request's session, revalidating it with the IdP
// when its refresh interval has passed. It returns nil if there is no
// session or the IdP revoked it.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) *session.Session {
	sess := s.loadSession(r)
	if sess == nil {
		return nil
	}
	fresh, changed := s.revalidate(r.Context(), sess)
	switch {
	case fresh == nil:
		s.clearSession(w, r)
	case changed:
		if err := s.writeSession(w, r, fresh); err != nil {
			s.log.Error("store refreshed session", "error", err, "user", fresh.Username)
		}
	}
	return fresh
}

// revalidate refreshes sess with the IdP if its refresh interval has
// passed. It returns the session to use (nil if the IdP revoked it) and
// whether it changed.
func (s *Server) revalidate(ctx context.Context, sess *session.Session) (*session.Session, bool) {
	// A live remote connection may hold this session too; whoever refreshed
	// last has the current refresh token, so both continue from the newest.
	changed := false
	if newer := s.live.newer(sess); newer != nil {
		sess, changed = newer, true
	}
	if sess.RefreshToken == "" || time.Now().Unix() < sess.RefreshAt {
		return sess, changed
	}
	// Another replica, or a connection that has closed since, may have
	// refreshed this session without the client getting the result.
	if stored := s.storedSession(ctx, sess); stored != nil {
		sess, changed = stored, true
		if time.Now().Unix() < sess.RefreshAt {
			return sess, true
		}
	}
	fresh, err := s.refreshes.do(refreshKey(sess), func() (*session.Session, error) {
		fresh, err := s.refresh(ctx, sess)
		switch {
		case err == nil:
			s.metrics.refreshes.WithLabelValues("success").Inc()
			s.storeSession(ctx, fresh)
		case errors.Is(err, errRevoked):
			s.metrics.refreshes.WithLabelValues("revoked").Inc()
		default:
			s.metrics.refreshes.WithLabelValues("error").Inc()
		}
		return fresh, err
	})
	switch {
	case err == nil:
		s.log.Debug("session refreshed", "user", fresh.Username, "groups", len(fresh.Groups))
		s.live.update(fresh)
		return fresh, true
	case errors.Is(err, errRevoked):
		s.log.Info("session revoked", "user", sess.Username, "sub", sess.Subject, "reason", err)
		s.emit(userEvent(EventSessionRevoked, sess, "", map[string]string{"reason": err.Error()}))
		return nil, false
	default:
		// The IdP is unreachable or misbehaving. Keep the user signed in
		// rather than locking everyone out; the next request retries once
		// the refresh result TTL has passed.
		s.log.Warn("session refresh failed, keeping session", "user", sess.Username, "error", err)
		return sess, changed
	}
}

// storedSession returns a newer refreshed copy of sess from the store, if
// there is one.
func (s *Server) storedSession(ctx context.Context, sess *session.Session) *session.Session {
	if sess.ID == "" {
		return nil
	}
	data, ok, err := s.store.SessionState(ctx, sess.ID, int64(sess.Gen))
	if err != nil {
		s.log.Warn("load session state", "error", err, "user", sess.Username)
	}
	var stored session.Session
	if !ok || s.refreshed.Open(sess.ID, data, &stored) != nil || stored.ID != sess.ID {
		return nil
	}
	return &stored
}

// storeSession saves a refreshed session as the newest state of its ID.
func (s *Server) storeSession(ctx context.Context, sess *session.Session) {
	if sess.ID == "" {
		return
	}
	// Runs within a refresh shared by several requests, like refresh.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	defer cancel()
	data, err := s.refreshed.Seal(sess.ID, sess)
	if err == nil {
		err = s.store.SaveSessionState(ctx, sess.ID, int64(sess.Gen), data, sess.Expiry)
	}
	if err != nil {
		s.log.Warn("store session state", "error", err, "user", sess.Username)
	}
}

// revoked reports whether sess was ended by logout or revoked by an admin.
func (s *Server) revoked(sess *session.Session) bool {
	return s.revocationReason(sess) != ""
}

// revocationReason explains why sess is no longer valid, or returns "". A
// session issued in the same millisecond as a revocation counts as revoked.
func (s *Server) revocationReason(sess *session.Session) string {
	rt := s.routes.Load()
	if sess.ID != "" && rt.ended[sess.ID] {
		return "you signed out"
	}
	if before := max(rt.revokedAll, rt.revokedUsers[sess.Subject]); before > 0 && sess.IssuedAt <= before {
		return "you were signed out by an administrator"
	}
	return ""
}

// endSession ends sess everywhere: its cookie or CLI token stops working
// and live remote connections using it close.
func (s *Server) endSession(ctx context.Context, sess *session.Session) error {
	if sess.ID == "" {
		return nil // issued before session IDs existed; expires on its own
	}
	if err := s.store.EndSession(ctx, sess.ID, sess.Expiry); err != nil {
		return err
	}
	return s.syncRevocations(ctx)
}

// liveSessions tracks sessions used by open remote connections, so the
// connection's watcher and the browser (or CLI) holding the same session
// share refresh results instead of redeeming stale refresh tokens, which
// IdPs that rotate refresh tokens would reject.
type liveSessions struct {
	mu sync.Mutex
	m  map[string]*liveSession
}

type liveSession struct {
	refs   int
	latest *session.Session
}

func (l *liveSessions) add(sess *session.Session) {
	if sess.ID == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]*liveSession{}
	}
	e := l.m[sess.ID]
	if e == nil {
		e = &liveSession{latest: sess}
		l.m[sess.ID] = e
	}
	e.refs++
}

func (l *liveSessions) remove(sess *session.Session) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.m[sess.ID]; e != nil {
		if e.refs--; e.refs <= 0 {
			delete(l.m, sess.ID)
		}
	}
}

// update records a refreshed session if it is live.
func (l *liveSessions) update(sess *session.Session) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.m[sess.ID]; e != nil && sess.Gen > e.latest.Gen {
		e.latest = sess
	}
}

// newer returns a more recently refreshed copy of sess, if there is one.
func (l *liveSessions) newer(sess *session.Session) *session.Session {
	if sess.ID == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.m[sess.ID]; e != nil && e.latest.Gen > sess.Gen {
		return e.latest
	}
	return nil
}

// refresh redeems the session's refresh token and rebuilds the identity
// from the new ID token, so group changes apply too.
func (s *Server) refresh(ctx context.Context, old *session.Session) (*session.Session, error) {
	// Shared with other waiting requests, so it must not end with this one.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	defer cancel()

	tok, err := s.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: old.RefreshToken}).Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.Response != nil &&
			(re.Response.StatusCode == http.StatusBadRequest || re.Response.StatusCode == http.StatusUnauthorized) {
			return nil, fmt.Errorf("%w: %s %s", errRevoked, re.ErrorCode, re.ErrorDescription)
		}
		return nil, err
	}

	sess := *old
	sess.Gen++
	if raw, _ := tok.Extra("id_token").(string); raw != "" {
		idt, err := s.verifier.Verify(ctx, raw)
		if err != nil {
			return nil, fmt.Errorf("verify refreshed id token: %w", err)
		}
		if idt.Subject != old.Subject {
			return nil, fmt.Errorf("%w: subject changed", errRevoked)
		}
		id, err := s.identity(idt)
		if err != nil {
			return nil, err
		}
		sess.Username, sess.Email, sess.Name, sess.Groups = id.Username, id.Email, id.Name, id.Groups
	}
	if tok.RefreshToken != "" {
		sess.RefreshToken = tok.RefreshToken
	}
	sess.RefreshAt = time.Now().Add(s.refreshInterval).Unix()
	return &sess, nil
}

func refreshKey(sess *session.Session) string {
	sum := sha256.Sum256([]byte(sess.RefreshToken))
	return string(sum[:])
}

// refreshGroup deduplicates refreshes of the same session: a page load
// fires many parallel requests, and IdPs that rotate refresh tokens would
// reject all but the first redemption.
type refreshGroup struct {
	ttl   time.Duration // how long results are reused
	mu    sync.Mutex
	calls map[string]*refreshCall
}

type refreshCall struct {
	done    chan struct{}
	sess    *session.Session
	err     error
	expires time.Time // zero while in flight
}

func (g *refreshGroup) do(key string, fn func() (*session.Session, error)) (*session.Session, error) {
	g.mu.Lock()
	now := time.Now()
	if c, ok := g.calls[key]; ok && (c.expires.IsZero() || now.Before(c.expires)) {
		g.mu.Unlock()
		<-c.done
		return c.sess, c.err
	}
	for k, c := range g.calls {
		if !c.expires.IsZero() && now.After(c.expires) {
			delete(g.calls, k)
		}
	}
	if g.calls == nil {
		g.calls = map[string]*refreshCall{}
	}
	c := &refreshCall{done: make(chan struct{})}
	g.calls[key] = c
	g.mu.Unlock()

	c.sess, c.err = fn()

	g.mu.Lock()
	c.expires = time.Now().Add(g.ttl)
	g.mu.Unlock()
	close(c.done)
	return c.sess, c.err
}
