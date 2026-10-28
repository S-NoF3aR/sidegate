// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"sidegate/internal/config"
	"sidegate/internal/store"
)

// The management API used by the Terraform provider. It authenticates with
// API tokens (never with the session cookie, so CSRF doesn't apply) and
// reads from the database rather than the in-memory routes, so a write
// through one replica is immediately visible through any other.

const tokenPrefix = "sgt_"

func (s *Server) apiRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/apps", s.api(s.apiListApps))
	mux.HandleFunc("POST /api/v1/apps", s.api(s.apiCreateApp))
	mux.HandleFunc("GET /api/v1/apps/{name}", s.api(s.apiGetApp))
	mux.HandleFunc("PUT /api/v1/apps/{name}", s.api(s.apiUpdateApp))
	mux.HandleFunc("DELETE /api/v1/apps/{name}", s.api(s.apiDeleteApp))
	// Group IDs may contain slashes (e.g. Keycloak group paths).
	mux.HandleFunc("GET /api/v1/groups", s.api(s.apiListGroups))
	mux.HandleFunc("GET /api/v1/groups/{id...}", s.api(s.apiGetGroup))
	mux.HandleFunc("PUT /api/v1/groups/{id...}", s.api(s.apiPutGroup))
	mux.HandleFunc("DELETE /api/v1/groups/{id...}", s.api(s.apiDeleteGroup))
	mux.HandleFunc("GET /api/v1/users", s.api(s.apiListUsers))
	mux.HandleFunc("POST /api/v1/sessions/revoke", s.api(s.apiRevokeSessions))
	mux.HandleFunc("POST /api/v1/sessions/revoke-all", s.api(s.apiRevokeAll))
	mux.HandleFunc("/api/v1/", s.api(func(w http.ResponseWriter, r *http.Request, _ store.Token) {
		apiError(w, http.StatusNotFound, "no such endpoint")
	}))
}

// newToken returns a new random API token and its ID.
func newToken() (token, id string) {
	b := make([]byte, 32)
	rand.Read(b)
	idb := make([]byte, 6)
	rand.Read(idb)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), hex.EncodeToString(idb)
}

// tokenHash is keyed with a secret derived from the session secret, so
// rows written directly into the database can't create working tokens.
func (s *Server) tokenHash(token string) string {
	m := hmac.New(sha256.New, s.apiKey)
	m.Write([]byte(token))
	return hex.EncodeToString(m.Sum(nil))
}

type apiHandler func(w http.ResponseWriter, r *http.Request, tok store.Token)

func (s *Server) api(h apiHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !strings.HasPrefix(raw, tokenPrefix) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sidegate"`)
			apiError(w, http.StatusUnauthorized, "missing or malformed bearer token")
			return
		}
		tok, err := s.store.TokenByHash(r.Context(), s.tokenHash(raw))
		if errors.Is(err, store.ErrNotFound) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sidegate", error="invalid_token"`)
			apiError(w, http.StatusUnauthorized, "invalid or revoked token")
			return
		} else if err != nil {
			s.log.Error("look up api token", "error", err)
			apiError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		if time.Since(tok.LastUsedAt) > time.Minute {
			if err := s.store.TouchToken(r.Context(), tok.ID); err != nil {
				s.log.Warn("record token use", "error", err)
			}
		}
		setLogName(r, "token:"+tok.Name)
		h(w, r, tok)
	}
}

func tokenActor(tok store.Token) string { return "token:" + tok.Name }

// apiApp is the API representation of an app. Lists are never null and
// always sorted, so clients can compare them reliably.
type apiApp struct {
	Name               string   `json:"name"`
	Subdomain          string   `json:"subdomain"`
	URL                string   `json:"url"` // read-only
	Upstream           string   `json:"upstream"`
	Title              string   `json:"title"`
	Description        string   `json:"description"`
	Icon               string   `json:"icon"`
	Category           string   `json:"category"`
	Public             bool     `json:"public"`
	Hidden             bool     `json:"hidden"`
	AllowedGroups      []string `json:"allowedGroups"`
	AllowedUsers       []string `json:"allowedUsers"`
	PublicPaths        []string `json:"publicPaths"`
	PassHostHeader     bool     `json:"passHostHeader"`
	HostHeader         string   `json:"hostHeader"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
	RequireMFA         bool     `json:"requireMFA"`
	MaxAuthAgeMinutes  int      `json:"maxAuthAgeMinutes"`
}

func (s *Server) toAPI(a config.App) apiApp {
	sorted := func(v []string) []string {
		out := slices.Clone(v)
		if out == nil {
			out = []string{}
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return apiApp{
		Name: a.Name, Subdomain: a.Subdomain, URL: s.appURL(a.Subdomain), Upstream: a.Upstream,
		Title: a.Title, Description: a.Description, Icon: a.Icon, Category: a.Category, Public: a.Public, Hidden: a.Hidden,
		AllowedGroups: sorted(a.AllowedGroups), AllowedUsers: sorted(a.AllowedUsers), PublicPaths: sorted(a.PublicPaths),
		PassHostHeader: a.PassHostHeader, HostHeader: a.HostHeader, InsecureSkipVerify: a.InsecureSkipVerify,
		RequireMFA: a.RequireMFA, MaxAuthAgeMinutes: a.MaxAuthAgeMinutes,
	}
}

func (x apiApp) toConfig() config.App {
	a := config.App{
		Name: x.Name, Subdomain: x.Subdomain, Upstream: x.Upstream, Title: x.Title,
		Description: x.Description, Icon: x.Icon, Category: x.Category, Public: x.Public, Hidden: x.Hidden,
		AllowedGroups: x.AllowedGroups, AllowedUsers: x.AllowedUsers, PublicPaths: x.PublicPaths,
		PassHostHeader: x.PassHostHeader, HostHeader: x.HostHeader, InsecureSkipVerify: x.InsecureSkipVerify,
		RequireMFA: x.RequireMFA, MaxAuthAgeMinutes: x.MaxAuthAgeMinutes,
	}
	a.Normalize()
	return a
}

// loadApp reads one app straight from the database.
func (s *Server) loadApp(r *http.Request, name string) (*config.App, error) {
	apps, _, _, err := s.store.Load(r.Context())
	if err != nil {
		return nil, err
	}
	for i := range apps {
		if apps[i].Name == name {
			return &apps[i], nil
		}
	}
	return nil, fmt.Errorf("%w: app %q", store.ErrNotFound, name)
}

func (s *Server) apiListApps(w http.ResponseWriter, r *http.Request, _ store.Token) {
	apps, _, _, err := s.store.Load(r.Context())
	if err != nil {
		s.apiStoreError(w, err)
		return
	}
	out := make([]apiApp, 0, len(apps))
	for _, a := range apps {
		out = append(out, s.toAPI(a))
	}
	apiJSON(w, http.StatusOK, out)
}

func (s *Server) apiGetApp(w http.ResponseWriter, r *http.Request, _ store.Token) {
	a, err := s.loadApp(r, r.PathValue("name"))
	if err != nil {
		s.apiStoreError(w, err)
		return
	}
	apiJSON(w, http.StatusOK, s.toAPI(*a))
}

func (s *Server) apiCreateApp(w http.ResponseWriter, r *http.Request, tok store.Token) {
	var in apiApp
	if !decodeJSON(w, r, &in) {
		return
	}
	s.apiSaveApp(w, r, tok, in.toConfig(), true)
}

func (s *Server) apiUpdateApp(w http.ResponseWriter, r *http.Request, tok store.Token) {
	var in apiApp
	if !decodeJSON(w, r, &in) {
		return
	}
	name := r.PathValue("name")
	if in.Name != "" && in.Name != name {
		apiError(w, http.StatusBadRequest, "apps cannot be renamed; the name in the body must match the URL")
		return
	}
	in.Name = name
	s.apiSaveApp(w, r, tok, in.toConfig(), false)
}

func (s *Server) apiSaveApp(w http.ResponseWriter, r *http.Request, tok store.Token, a config.App, create bool) {
	if err := a.Validate(s.domain, s.portalHost); err != nil {
		apiValidationError(w, err)
		return
	}
	var err error
	if create {
		err = s.store.CreateApp(r.Context(), tokenActor(tok), a)
	} else {
		err = s.store.UpdateApp(r.Context(), tokenActor(tok), a)
	}
	if err != nil {
		s.apiStoreError(w, err)
		return
	}
	s.syncAfterWrite(r)
	saved, err := s.loadApp(r, a.Name)
	if err != nil {
		s.apiStoreError(w, err)
		return
	}
	status := http.StatusOK
	if create {
		status = http.StatusCreated
	}
	apiJSON(w, status, s.toAPI(*saved))
}

func (s *Server) apiDeleteApp(w http.ResponseWriter, r *http.Request, tok store.Token) {
	if err := s.store.DeleteApp(r.Context(), tokenActor(tok), r.PathValue("name")); err != nil {
		s.apiStoreError(w, err)
		return
	}
	s.syncAfterWrite(r)
	w.WriteHeader(http.StatusNoContent)
}

type apiGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *Server) loadGroups(r *http.Request) ([]apiGroup, error) {
	_, groups, _, err := s.store.Load(r.Context())
	out := make([]apiGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, apiGroup{ID: g.ID, Name: g.Name})
	}
	return out, err
}

func (s *Server) apiListGroups(w http.ResponseWriter, r *http.Request, _ store.Token) {
	groups, err := s.loadGroups(r)
	if err != nil {
		s.apiStoreError(w, err)
		return
	}
	apiJSON(w, http.StatusOK, groups)
}

func (s *Server) apiGetGroup(w http.ResponseWriter, r *http.Request, _ store.Token) {
	groups, err := s.loadGroups(r)
	if err != nil {
		s.apiStoreError(w, err)
		return
	}
	id := r.PathValue("id")
	for _, g := range groups {
		if g.ID == id {
			apiJSON(w, http.StatusOK, g)
			return
		}
	}
	apiError(w, http.StatusNotFound, "group "+id+" not found")
}

// apiPutGroup creates or renames the group with the ID from the URL.
func (s *Server) apiPutGroup(w http.ResponseWriter, r *http.Request, tok store.Token) {
	var in apiGroup
	if !decodeJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	if in.ID != "" && in.ID != id {
		apiError(w, http.StatusBadRequest, "the id in the body must match the URL")
		return
	}
	if err := s.store.SaveGroup(r.Context(), tokenActor(tok), store.Group{ID: id, Name: in.Name}); err != nil {
		s.apiStoreError(w, err)
		return
	}
	s.syncAfterWrite(r)
	apiJSON(w, http.StatusOK, apiGroup{ID: id, Name: strings.TrimSpace(in.Name)})
}

func (s *Server) apiDeleteGroup(w http.ResponseWriter, r *http.Request, tok store.Token) {
	if err := s.store.DeleteGroup(r.Context(), tokenActor(tok), r.PathValue("id")); err != nil {
		s.apiStoreError(w, err)
		return
	}
	s.syncAfterWrite(r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiListUsers(w http.ResponseWriter, r *http.Request, _ store.Token) {
	users, err := s.store.Users(r.Context())
	if err != nil {
		s.apiStoreError(w, err)
		return
	}
	if users == nil {
		users = []store.User{}
	}
	apiJSON(w, http.StatusOK, users)
}

// apiRevokeSessions signs a user out everywhere, e.g. from an offboarding
// workflow. Body: {"subject": "..."}.
func (s *Server) apiRevokeSessions(w http.ResponseWriter, r *http.Request, tok store.Token) {
	var in struct {
		Subject string `json:"subject"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.store.RevokeSessions(r.Context(), tokenActor(tok), in.Subject); err != nil {
		s.apiStoreError(w, err)
		return
	}
	s.syncAfterWrite(r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiRevokeAll(w http.ResponseWriter, r *http.Request, tok store.Token) {
	if err := s.store.RevokeAllSessions(r.Context(), tokenActor(tok)); err != nil {
		s.apiStoreError(w, err)
		return
	}
	s.syncAfterWrite(r)
	w.WriteHeader(http.StatusNoContent)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func (s *Server) apiStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		apiError(w, http.StatusNotFound, strings.TrimPrefix(err.Error(), store.ErrNotFound.Error()+": ")+" not found")
	case errors.Is(err, store.ErrConflict):
		apiError(w, http.StatusConflict, strings.TrimPrefix(err.Error(), store.ErrConflict.Error()+": "))
	default:
		s.log.Error("api store error", "error", err)
		apiError(w, http.StatusInternalServerError, "internal error")
	}
}

func apiValidationError(w http.ResponseWriter, err error) {
	var details []string
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		for _, e := range joined.Unwrap() {
			details = append(details, e.Error())
		}
	} else {
		details = []string{err.Error()}
	}
	apiJSON(w, http.StatusBadRequest, map[string]any{"error": "validation failed", "details": details})
}

func apiError(w http.ResponseWriter, status int, msg string) {
	apiJSON(w, status, map[string]string{"error": msg})
}

func apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
