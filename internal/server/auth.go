// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"sidegate/internal/session"
	"sidegate/internal/store"
)

const stateLifetime = 10 * time.Minute

// oauthErrorCode matches OAuth/OIDC error codes such as access_denied.
var oauthErrorCode = regexp.MustCompile(`^[a-z_]{1,40}$`)

// oauthState is kept in a short-lived cookie between /oauth2/start and the
// callback. Each login attempt gets its own cookie, so several tabs can sign
// in concurrently without clobbering each other's state.
type oauthState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Redirect string `json:"r"`
	Expiry   int64  `json:"e"`
	// Step-up requirements the resulting sign-in must meet.
	MFA    bool `json:"m,omitempty"`
	MaxAge int  `json:"a,omitempty"`
	// For Sidegate CLI sign-ins: where to deliver the CLI token.
	CLIPort      int    `json:"cp,omitempty"`
	CLIState     string `json:"cs,omitempty"`
	CLIChallenge string `json:"cc,omitempty"`
}

func (s *Server) stateCookieName(state string) string {
	return s.cookieName + "_oauth_" + state[:8]
}

// loginURL returns the portal URL that starts a login returning to rd,
// optionally requiring MFA or an authentication within maxAge seconds.
func (s *Server) loginURL(rd string, mfa bool, maxAge int) string {
	u := s.public.JoinPath("/oauth2/start")
	q := url.Values{"rd": {rd}}
	if mfa {
		q.Set("mfa", "1")
	}
	if maxAge > 0 {
		q.Set("max_age", strconv.Itoa(maxAge))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// isNavigation reports whether a browser can follow a login redirect for
// r; API calls, fetches and WebSockets can't.
func isNavigation(r *http.Request) bool {
	mode := r.Header.Get("Sec-Fetch-Mode")
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		(mode == "" || mode == "navigate") &&
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// requireStepUp sends the user back to the IdP to sign in with MFA and/or
// freshly.
func (s *Server) requireStepUp(w http.ResponseWriter, r *http.Request, mfa bool, maxAge int) {
	if !isNavigation(r) {
		// Clients such as the Sidegate CLI use the details to sign in again.
		apiJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "step-up authentication required", "mfa": mfa, "maxAge": maxAge,
		})
		return
	}
	rd := s.public.Scheme + "://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, s.loginURL(rd, mfa, maxAge), http.StatusFound)
}

func (s *Server) requireLogin(w http.ResponseWriter, r *http.Request) {
	if !isNavigation(r) {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	rd := s.public.Scheme + "://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, s.loginURL(rd, false, 0), http.StatusFound)
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	st := oauthState{Redirect: s.safeRedirect(q.Get("rd")), MFA: q.Get("mfa") == "1"}
	if n, err := strconv.Atoi(q.Get("max_age")); err == nil && n > 0 {
		st.MaxAge = n
	}
	s.startLogin(w, r, st)
}

// startLogin redirects to the IdP. st carries the sign-in's purpose; the
// protocol fields are filled in here.
func (s *Server) startLogin(w http.ResponseWriter, r *http.Request, st oauthState) {
	st.State = randomString()
	st.Nonce = randomString()
	st.Verifier = oauth2.GenerateVerifier()
	st.Expiry = time.Now().Add(stateLifetime).Unix()
	name := s.stateCookieName(st.State)
	val, err := s.states.Seal(name, st)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    val,
		Path:     "/oauth2/",
		MaxAge:   int(stateLifetime.Seconds()),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
	opts := []oauth2.AuthCodeOption{oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)}
	if st.MFA {
		for k, v := range s.mfa.AuthParams {
			opts = append(opts, oauth2.SetAuthURLParam(k, v))
		}
	}
	if st.MaxAge > 0 {
		// max_age asks the IdP to re-authenticate older sign-ins; prompt=login
		// forces it on IdPs that ignore max_age.
		opts = append(opts, oauth2.SetAuthURLParam("max_age", strconv.Itoa(st.MaxAge)),
			oauth2.SetAuthURLParam("prompt", "login"))
	}
	target := s.oauth.AuthCodeURL(st.State, opts...)
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.metrics.logins.WithLabelValues("failure").Inc()
		s.log.Warn("identity provider returned error", "error", e, "description", q.Get("error_description"))
		// Anyone can craft this URL, so only a recognizable error code is
		// shown, never free text from the query.
		msg := "The identity provider did not complete the sign-in. Please try again or contact your administrator."
		if oauthErrorCode.MatchString(e) {
			msg += " (" + e + ")"
		}
		s.renderError(w, r, http.StatusUnauthorized, "Sign-in failed", msg)
		return
	}

	state := q.Get("state")
	var st oauthState
	if len(state) < 8 || !s.readState(r, state, &st) {
		s.renderError(w, r, http.StatusBadRequest, "Sign-in expired",
			"The sign-in attempt is unknown or took too long. Please try again.")
		return
	}
	// The state cookie is single-use.
	http.SetCookie(w, &http.Cookie{Name: s.stateCookieName(state), Path: "/oauth2/", MaxAge: -1, Secure: s.secure, HttpOnly: true})

	tok, err := s.oauth.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		s.metrics.logins.WithLabelValues("failure").Inc()
		s.log.Warn("code exchange failed", "error", err)
		s.renderError(w, r, http.StatusBadGateway, "Sign-in failed", "Could not redeem the authorization code with the identity provider.")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		s.renderError(w, r, http.StatusBadGateway, "Sign-in failed", "The identity provider did not return an ID token.")
		return
	}
	idt, err := s.verifier.Verify(r.Context(), raw)
	if err != nil || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		s.metrics.logins.WithLabelValues("failure").Inc()
		s.log.Warn("id token rejected", "error", err)
		s.renderError(w, r, http.StatusUnauthorized, "Sign-in failed", "The ID token could not be verified.")
		return
	}

	sess, err := s.identity(idt)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	now := time.Now()
	sess.ID = randomString()
	sess.IssuedAt = now.UnixMilli()
	sess.AuthTime, sess.MFA = s.authStrength(idt, now)
	sess.Expiry = now.Add(s.lifetime).Unix()
	sess.RefreshToken = tok.RefreshToken
	sess.RefreshAt = now.Add(s.refreshInterval).Unix()
	if tok.RefreshToken == "" {
		s.log.Warn("identity provider returned no refresh token; the session cannot be revalidated before it expires (for Entra ID add offline_access to oidc.scopes)",
			"user", sess.Username)
	}
	// CLI sign-ins hand the session to the Sidegate CLI instead of the browser.
	if st.CLIPort == 0 {
		if err := s.writeSession(w, r, sess); err != nil {
			s.log.Error("store session", "error", err, "groups", len(sess.Groups))
			s.renderError(w, r, http.StatusInternalServerError, "Sign-in failed", "Your session is too large to store in cookies.")
			return
		}
	}
	s.metrics.logins.WithLabelValues("success").Inc()
	s.emit(userEvent(EventLogin, sess, "", map[string]string{"mfa": strconv.FormatBool(sess.MFA), "cli": strconv.FormatBool(st.CLIPort != 0)}))
	s.log.Info("login", "user", sess.Username, "sub", sess.Subject, "groups", len(sess.Groups),
		"refreshable", sess.RefreshToken != "", "mfa", sess.MFA, "cli", st.CLIPort != 0)
	if err := s.store.RecordLogin(r.Context(), store.User{
		Subject: sess.Subject, Username: sess.Username, Email: sess.Email, Name: sess.Name,
	}); err != nil {
		s.log.Warn("record login", "error", err)
	}

	// A step-up the IdP didn't honor must not bounce back to the app, which
	// would just send the user here again.
	if st.MFA && !sess.MFA {
		s.renderError(w, r, http.StatusForbidden, "Multi-factor authentication required",
			"This application requires a sign-in with multi-factor authentication, but the identity provider didn't confirm one. Sign out and sign in again with MFA, or contact your administrator.")
		return
	}
	if st.MaxAge > 0 && sess.AuthTime == 0 {
		s.renderError(w, r, http.StatusForbidden, "Fresh sign-in required",
			"This application requires a recent sign-in, but the identity provider didn't confirm when you signed in (auth_time). Contact your administrator.")
		return
	}
	if st.MaxAge > 0 && now.Unix()-sess.AuthTime > int64(st.MaxAge)+60 {
		s.renderError(w, r, http.StatusForbidden, "Fresh sign-in required",
			"This application requires a recent sign-in, but the identity provider reused an older one. Sign out and sign in again.")
		return
	}
	if st.CLIPort != 0 {
		s.cliRedirect(w, r, st, sess)
		return
	}
	http.Redirect(w, r, st.Redirect, http.StatusFound)
}

func (s *Server) readState(r *http.Request, state string, st *oauthState) bool {
	name := s.stateCookieName(state)
	c, err := r.Cookie(name)
	if err != nil || s.states.Open(name, c.Value, st) != nil {
		return false
	}
	return time.Now().Unix() < st.Expiry &&
		subtle.ConstantTimeCompare([]byte(st.State), []byte(state)) == 1
}

// identity builds a session from the claims of an ID token. Expiry and
// refresh fields are left to the caller.
func (s *Server) identity(idt *oidc.IDToken) (*session.Session, error) {
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return nil, err
	}
	str := func(k string) string { v, _ := claims[k].(string); return v }

	sess := &session.Session{
		Subject:  idt.Subject,
		Username: str(s.oidcCfg.UsernameClaim),
		Email:    str("email"),
		Name:     str("name"),
	}
	// An email the IdP marks as unverified may be chosen by the user, so
	// it must not grant access through allowedUsers or admin.users.
	if v, ok := claims["email_verified"]; ok && (v == false || v == "false") {
		sess.Email = ""
		if s.oidcCfg.UsernameClaim == "email" {
			sess.Username = ""
		}
	}
	if sess.Username == "" {
		sess.Username = sess.Email
	}

	// Entra ID omits the groups claim when a user is in too many groups
	// and points to Microsoft Graph instead ("group overage").
	if names, ok := claims["_claim_names"].(map[string]any); ok && names[s.oidcCfg.GroupsClaim] != nil {
		s.log.Warn("groups claim overage: configure the app registration to emit only groups assigned to the application",
			"user", sess.Username)
	}

	known := s.routes.Load().groups
	for _, g := range claimStrings(lookupClaim(claims, s.oidcCfg.GroupsClaim)) {
		if known[g] {
			sess.Groups = append(sess.Groups, g)
		}
	}
	return sess, nil
}

// authStrength returns when the user authenticated (0 if unknown) and
// whether that included MFA, judged by the configured amr/acr values.
func (s *Server) authStrength(idt *oidc.IDToken, now time.Time) (authTime int64, mfa bool) {
	var claims struct {
		AuthTime float64 `json:"auth_time"`
		AMR      []any   `json:"amr"`
		ACR      any     `json:"acr"`
		ACRS     []any   `json:"acrs"` // Entra ID authentication contexts
	}
	if err := idt.Claims(&claims); err != nil {
		return 0, false
	}
	// Without a plausible auth_time, the IdP may have reused an old sign-in
	// without saying so; 0 (unknown) fails every sign-in age requirement.
	authTime = int64(claims.AuthTime)
	if authTime <= 0 || authTime > now.Unix()+60 {
		authTime = 0
	}
	has := func(values []string, got []string) bool {
		for _, g := range got {
			if slices.Contains(values, g) {
				return true
			}
		}
		return false
	}
	acr := claimStrings(claims.ACR)
	acr = append(acr, claimStrings(claims.ACRS)...)
	mfa = has(s.mfa.AMR, claimStrings(claims.AMR)) || has(s.mfa.ACR, acr)
	return authTime, mfa
}

func lookupClaim(claims map[string]any, path string) any {
	var cur any = claims
	for part := range strings.SplitSeq(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

func claimStrings(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// handleLogoutPage asks before signing out, so other websites can't sign
// users out by linking or embedding /oauth2/logout.
func (s *Server) handleLogoutPage(w http.ResponseWriter, r *http.Request) {
	sess := s.loadSession(r)
	s.render(w, http.StatusOK, "message", messageData{
		Title: "Sign out?", Message: "This signs you out of all applications.",
		Action: "Sign out", PostTo: s.public.JoinPath("/oauth2/logout").String(),
		User: sess, Admin: s.isAdmin(sess),
	})
}

// sameSiteOrigin reports whether a request's Origin is the portal or one of
// the app hosts (or absent, for clients that don't send one).
func (s *Server) sameSiteOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil || u.Scheme != s.public.Scheme {
		return false
	}
	h := canonicalHost(u.Host)
	return h == s.portalHost || strings.HasSuffix(h, "."+s.domain)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Sign-out buttons live on the portal and on app hosts' pages; other
	// websites must not be able to post here.
	if !s.sameSiteOrigin(r) {
		s.renderError(w, r, http.StatusForbidden, "Sign-out not allowed", "Use the Sign out button in the portal.")
		return
	}
	// End the session server-side too, so copies of the cookie stop
	// working and open remote connections close.
	if sess := s.loadSession(r); sess != nil {
		if err := s.endSession(r.Context(), sess); err != nil {
			s.log.Error("end session on logout", "error", err, "user", sess.Username)
		} else {
			s.log.Info("logout", "user", sess.Username, "sub", sess.Subject)
			s.emit(userEvent(EventLogout, sess, "", nil))
		}
	}
	s.clearSession(w, r)
	target := s.public.JoinPath("/oauth2/signed-out").String()
	if s.providerLogout && s.endSessionURL != "" {
		if u, err := url.Parse(s.endSessionURL); err == nil {
			q := u.Query()
			q.Set("client_id", s.oauth.ClientID)
			q.Set("post_logout_redirect_uri", target)
			u.RawQuery = q.Encode()
			target = u.String()
		}
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// safeRedirect only allows returning to the portal or one of the app
// subdomains, preventing open redirects.
func (s *Server) safeRedirect(rd string) string {
	fallback := s.public.String() + "/"
	u, err := url.Parse(rd)
	if err != nil || !u.IsAbs() || u.Scheme != s.public.Scheme || u.User != nil {
		return fallback
	}
	h := canonicalHost(u.Host)
	if h != s.portalHost && h != s.domain && !strings.HasSuffix(h, "."+s.domain) {
		return fallback
	}
	return u.String()
}

func randomString() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
