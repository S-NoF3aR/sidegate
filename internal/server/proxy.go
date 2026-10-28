// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Identity headers sent to upstreams. They use the same names as
// oauth2-proxy so existing "auth proxy" integrations (Grafana, etc.) work.
const (
	headerUser     = "X-Forwarded-User"
	headerEmail    = "X-Forwarded-Email"
	headerUsername = "X-Forwarded-Preferred-Username"
	headerGroups   = "X-Forwarded-Groups"
)

// spoofable lists headers a client must never be able to inject, normalized
// to lower case with '_' replaced by '-' (many frameworks treat them alike).
var spoofable = map[string]bool{
	"x-forwarded-user":                  true,
	"x-forwarded-email":                 true,
	"x-forwarded-preferred-username":    true,
	"x-forwarded-groups":                true,
	"x-auth-request-user":               true,
	"x-auth-request-email":              true,
	"x-auth-request-preferred-username": true,
	"x-auth-request-groups":             true,
	"x-auth-request-access-token":       true,
	"x-sidegate-jwt-assertion":          true,
	"remote-user":                       true,
}

func (s *Server) newProxy(a *app) (http.Handler, *http.Transport) {
	target, _ := url.Parse(a.Upstream) // validated by config
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if a.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	rp := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-Proto", s.public.Scheme)
			switch {
			case a.HostHeader != "":
				pr.Out.Host = a.HostHeader
			case a.PassHostHeader:
				pr.Out.Host = pr.In.Host
			}
			for k := range pr.Out.Header {
				if spoofable[strings.ReplaceAll(strings.ToLower(k), "_", "-")] {
					delete(pr.Out.Header, k)
				}
			}
			s.stripProxyCookies(pr.Out.Header)
			if sess := sessionFrom(pr.In.Context()); sess != nil {
				pr.Out.Header.Set(headerUser, sess.Username)
				pr.Out.Header.Set(headerUsername, sess.Username)
				if sess.Email != "" {
					pr.Out.Header.Set(headerEmail, sess.Email)
				}
				if len(sess.Groups) > 0 {
					pr.Out.Header.Set(headerGroups, s.groupList(sess.Groups))
				}
				if jwt, err := s.assertion(sess, a); err == nil {
					pr.Out.Header.Set(jwtHeader, jwt)
				} else {
					s.log.Error("sign identity assertion", "app", a.Name, "error", err)
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			rewriteInternalHost(resp, internalHosts(target, a.HostHeader), s.public.Scheme)
			s.dropProxyCookies(resp.Header)
			if s.secure {
				// The proxy's own HSTS policy (set in ServeHTTP) covers
				// the whole domain; an app's must not weaken or duplicate it.
				resp.Header.Del("Strict-Transport-Security")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return
			}
			s.metrics.upstreamErrors.WithLabelValues(a.Name).Inc()
			s.log.Warn("upstream error", "app", a.Name, "upstream", a.Upstream, "error", err)
			s.renderError(w, r, http.StatusBadGateway, "Application unavailable",
				a.DisplayTitle()+" is not responding right now. Please try again later.")
		},
	}
	return rp, transport
}

// groupNames maps group IDs to their friendly names where one exists.
func (s *Server) groupNames(groups []string) []string {
	names := s.routes.Load().groupNames
	out := make([]string, len(groups))
	for i, g := range groups {
		if n, ok := names[g]; ok {
			out[i] = n
		} else {
			out[i] = g
		}
	}
	return out
}

// groupList renders groups for the upstream header.
func (s *Server) groupList(groups []string) string {
	return strings.Join(s.groupNames(groups), ",")
}

// internalHosts returns the lower-cased host names the upstream knows
// itself by, with and without port.
func internalHosts(target *url.URL, hostHeader string) map[string]bool {
	hosts := map[string]bool{}
	for _, h := range []string{target.Host, hostHeader} {
		if h == "" {
			continue
		}
		h = strings.ToLower(h)
		hosts[h] = true
		if host, _, err := net.SplitHostPort(h); err == nil {
			hosts[host] = true
		}
	}
	return hosts
}

// rewriteInternalHost fixes responses that point the browser at the
// upstream's internal host name: absolute redirects are sent to the app's
// public host instead, and cookie Domain attributes for the internal host
// are dropped so the browser scopes the cookie to the app's host.
func rewriteInternalHost(resp *http.Response, internal map[string]bool, scheme string) {
	public := resp.Request.Header.Get("X-Forwarded-Host") // the original host, set by SetXForwarded
	if public == "" {
		return
	}
	for _, key := range []string{"Location", "Content-Location"} {
		loc := resp.Header.Get(key)
		if loc == "" {
			continue
		}
		u, err := url.Parse(loc)
		if err != nil || !u.IsAbs() || !internal[strings.ToLower(u.Host)] {
			continue
		}
		u.Scheme, u.Host = scheme, public
		resp.Header.Set(key, u.String())
	}
	cookies := resp.Header.Values("Set-Cookie")
	for i, c := range cookies {
		parts := strings.Split(c, ";")
		kept := parts[:1]
		for _, attr := range parts[1:] {
			name, value, _ := strings.Cut(strings.TrimSpace(attr), "=")
			if strings.EqualFold(name, "domain") && internal[strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "."))] {
				continue
			}
			kept = append(kept, attr)
		}
		cookies[i] = strings.Join(kept, ";")
	}
}

// isProxyCookie reports whether name is one of the proxy's cookies: the
// session cookie, its chunks and the login state cookies.
func (s *Server) isProxyCookie(name string) bool {
	return name == s.cookieName || strings.HasPrefix(name, s.cookieName+"_")
}

// dropProxyCookies removes Set-Cookie headers of an upstream response that
// would set one of the proxy's cookies. All apps share the parent domain, so
// an app could otherwise replace the user's session with another one
// (session fixation) or sign the user out.
func (s *Server) dropProxyCookies(h http.Header) {
	cookies := h.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	var keep []string
	for _, c := range cookies {
		name, _, _ := strings.Cut(c, "=")
		if s.isProxyCookie(strings.TrimSpace(name)) {
			continue
		}
		keep = append(keep, c)
	}
	h.Del("Set-Cookie")
	for _, c := range keep {
		h.Add("Set-Cookie", c)
	}
}

// stripProxyCookies removes the proxy's own cookies so upstreams never see
// (and can never leak) the user's session.
func (s *Server) stripProxyCookies(h http.Header) {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	var keep []string
	for _, line := range lines {
		for part := range strings.SplitSeq(line, ";") {
			part = strings.TrimSpace(part)
			name, _, _ := strings.Cut(part, "=")
			// Covers the session cookie, its chunks and login state cookies.
			if part == "" || s.isProxyCookie(name) {
				continue
			}
			keep = append(keep, part)
		}
	}
	h.Del("Cookie")
	if len(keep) > 0 {
		h.Set("Cookie", strings.Join(keep, "; "))
	}
}
