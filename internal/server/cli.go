// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sidegate/internal/session"
)

// The Sidegate CLI signs in like this (the OAuth pattern for native apps,
// RFC 8252, with PKCE):
//
//  1. The CLI picks a random verifier, listens on 127.0.0.1:<port> and opens
//     the browser at /cli/login?port=<port>&state=<random>&challenge=<S256 of
//     the verifier>.
//  2. The user confirms; the proxy runs a regular OIDC sign-in.
//  3. The callback sends the browser to http://127.0.0.1:<port>/callback
//     with a short-lived code (the sealed session and challenge).
//  4. The CLI posts the code and the verifier to /cli/token and receives
//     the CLI token, which it sends as "Authorization: Bearer sgs_...".
//
// The code ends up in the browser history, but it expires after a minute
// and is useless without the verifier, which never leaves the CLI.
//
// The CLI gets its own sign-in (and refresh token) instead of a copy of the
// browser's, so the two never redeem the same refresh token. CLI tokens are
// revalidated, revoked and expire exactly like browser sessions; when the
// proxy refreshes one, it returns the new token in the X-Sidegate-Session
// response header.

const (
	cliTokenPrefix = "sgs_"
	cliTokenAAD    = "cli"
	cliTokenHeader = "X-Sidegate-Session"
	cliCodeAAD     = "cli-code"
	cliCodeTTL     = time.Minute
)

// cliCode is what the browser carries back to the CLI.
type cliCode struct {
	Session   *session.Session `json:"s"`
	Challenge string           `json:"c"`
	Expiry    int64            `json:"e"`
}

// cliChallengeRe matches an S256 PKCE challenge (base64url of SHA-256).
var cliChallengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

var cliStateRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

type cliLoginData struct {
	User      *session.Session
	Admin     bool
	Port      int
	State     string
	Challenge string
	MFA       bool
	MaxAge    int
	Error     string
}

func parseCLILogin(v url.Values) (cliLoginData, bool) {
	d := cliLoginData{State: v.Get("state"), Challenge: v.Get("challenge"), MFA: v.Get("mfa") == "1"}
	port, err := strconv.Atoi(v.Get("port"))
	if err != nil || port < 1024 || port > 65535 || !cliStateRe.MatchString(d.State) || !cliChallengeRe.MatchString(d.Challenge) {
		return d, false
	}
	d.Port = port
	if n, err := strconv.Atoi(v.Get("max_age")); err == nil && n > 0 {
		d.MaxAge = n
	}
	return d, true
}

// handleCLILoginPage asks the user to confirm before the CLI is signed in,
// so a web page can't silently mint a CLI token by linking here.
func (s *Server) handleCLILoginPage(w http.ResponseWriter, r *http.Request) {
	d, ok := parseCLILogin(r.URL.Query())
	if !ok {
		s.renderError(w, r, http.StatusBadRequest, "Invalid CLI sign-in", "Start the sign-in from the Sidegate CLI.")
		return
	}
	d.User = s.loadSession(r)
	d.Admin = s.isAdmin(d.User)
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, http.StatusOK, "cli-login", d)
}

func (s *Server) handleCLILogin(w http.ResponseWriter, r *http.Request) {
	// The confirmation must come from our own page.
	if o := r.Header.Get("Origin"); o != s.public.String() {
		s.renderError(w, r, http.StatusForbidden, "Invalid CLI sign-in", "Start the sign-in from the Sidegate CLI.")
		return
	}
	r.ParseForm()
	d, ok := parseCLILogin(r.PostForm)
	if !ok {
		s.renderError(w, r, http.StatusBadRequest, "Invalid CLI sign-in", "Start the sign-in from the Sidegate CLI.")
		return
	}
	s.startLogin(w, r, oauthState{
		Redirect: s.public.String() + "/", MFA: d.MFA, MaxAge: d.MaxAge,
		CLIPort: d.Port, CLIState: d.State, CLIChallenge: d.Challenge,
	})
}

// cliRedirect hands a freshly signed-in session to the waiting CLI.
func (s *Server) cliRedirect(w http.ResponseWriter, r *http.Request, st oauthState, sess *session.Session) {
	code, err := s.cliCodes.Seal(cliCodeAAD, cliCode{Session: sess, Challenge: st.CLIChallenge, Expiry: time.Now().Add(cliCodeTTL).Unix()})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	q := url.Values{"state": {st.CLIState}, "code": {code}}
	http.Redirect(w, r, fmt.Sprintf("http://127.0.0.1:%d/callback?%s", st.CLIPort, q.Encode()), http.StatusFound)
}

func (s *Server) cliToken(sess *session.Session) (string, error) {
	sealed, err := s.cliTokens.Seal(cliTokenAAD, sess)
	if err != nil {
		return "", err
	}
	return cliTokenPrefix + sealed, nil
}

// handleCLIToken exchanges the code from the sign-in for a CLI token,
// given the verifier whose S256 challenge started the sign-in.
func (s *Server) handleCLIToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	var c cliCode
	sum := sha256.Sum256([]byte(req.Verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if s.cliCodes.Open(cliCodeAAD, req.Code, &c) != nil || c.Session == nil || time.Now().Unix() > c.Expiry ||
		subtle.ConstantTimeCompare([]byte(challenge), []byte(c.Challenge)) != 1 {
		apiError(w, http.StatusBadRequest, "invalid or expired sign-in code")
		return
	}
	if s.revoked(c.Session) {
		apiError(w, http.StatusUnauthorized, "session revoked")
		return
	}
	token, err := s.cliToken(c.Session)
	if err != nil {
		s.log.Error("seal CLI token", "error", err)
		apiError(w, http.StatusInternalServerError, "could not issue a token")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	apiJSON(w, http.StatusOK, map[string]string{"token": token})
}

// handleCLILogout ends the CLI token's session (sidegate logout).
func (s *Server) handleCLILogout(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "+cliTokenPrefix)
	var sess session.Session
	if !ok || s.cliTokens.Open(cliTokenAAD, raw, &sess) != nil {
		apiError(w, http.StatusUnauthorized, "invalid CLI token")
		return
	}
	if err := s.endSession(r.Context(), &sess); err != nil {
		s.log.Error("end CLI session", "error", err)
		apiError(w, http.StatusInternalServerError, "could not end the session")
		return
	}
	s.log.Info("cli logout", "user", sess.Username, "sub", sess.Subject)
	s.emit(userEvent(EventLogout, &sess, "", map[string]string{"cli": "true"}))
	w.WriteHeader(http.StatusNoContent)
}

// authenticateBearer authenticates a request carrying a CLI token,
// revalidating it like a browser session.
func (s *Server) authenticateBearer(w http.ResponseWriter, r *http.Request) *session.Session {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "+cliTokenPrefix)
	if !ok {
		return nil
	}
	var sess session.Session
	if s.cliTokens.Open(cliTokenAAD, raw, &sess) != nil || !sess.Valid(time.Now()) {
		return nil
	}
	if s.revoked(&sess) {
		s.metrics.revoked.Inc()
		return nil
	}
	fresh, changed := s.revalidate(r.Context(), &sess)
	if fresh != nil && changed {
		if token, err := s.cliToken(fresh); err == nil {
			w.Header().Set(cliTokenHeader, token)
		}
	}
	return fresh
}
