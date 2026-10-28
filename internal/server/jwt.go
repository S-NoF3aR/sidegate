// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"sidegate/internal/session"
)

// jwtHeader carries a signed assertion of the user's identity to upstreams,
// so they can verify it instead of trusting plain headers.
const jwtHeader = "X-Sidegate-Jwt-Assertion"

const jwtLifetime = 5 * time.Minute

type jwtSigner struct {
	signer jose.Signer
	jwks   []byte
}

// newJWTSigner derives an ES256 key from the session secret, so every
// replica signs with the same key without storing it anywhere.
func newJWTSigner(secret string) (*jwtSigner, error) {
	var key *ecdsa.PrivateKey
	for i := 0; key == nil; i++ {
		seed, err := session.DeriveKey(secret, fmt.Sprintf("jwt-signing %d", i))
		if err != nil {
			return nil, err
		}
		// Fails only if the seed is zero or not below the curve order
		// (probability ~2^-32); then the next derivation is used.
		key, _ = ecdsa.ParseRawPrivateKey(elliptic.P256(), seed)
	}
	pub := jose.JSONWebKey{Key: &key.PublicKey, Algorithm: string(jose.ES256), Use: "sig"}
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	pub.KeyID = base64.RawURLEncoding.EncodeToString(thumb)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: pub.KeyID}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	if err != nil {
		return nil, err
	}
	return &jwtSigner{signer: signer, jwks: jwks}, nil
}

// assertion signs the identity of sess for one app. The audience is the
// app's origin, so a token received by one app can't be replayed to another.
func (s *Server) assertion(sess *session.Session, a *app) (string, error) {
	now := time.Now()
	claims := map[string]any{
		"iss":                s.public.String(),
		"aud":                strings.TrimSuffix(a.URL, "/"),
		"sub":                sess.Subject,
		"iat":                now.Unix(),
		"nbf":                now.Add(-30 * time.Second).Unix(),
		"exp":                now.Add(jwtLifetime).Unix(),
		"preferred_username": sess.Username,
		"groups":             s.groupNames(sess.Groups),
		"mfa":                sess.MFA,
	}
	if sess.Email != "" {
		claims["email"] = sess.Email
	}
	if sess.Name != "" {
		claims["name"] = sess.Name
	}
	if sess.AuthTime > 0 {
		claims["auth_time"] = sess.AuthTime
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := s.jwt.signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}
