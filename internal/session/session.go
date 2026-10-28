// SPDX-License-Identifier: AGPL-3.0-only

// Package session encrypts and authenticates cookie payloads.
//
// Sessions live entirely in the cookie, so any number of proxy replicas can
// serve a user without shared storage.
package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// Session is the identity stored in the session cookie.
type Session struct {
	// ID identifies one sign-in, so a logout can end exactly this session.
	ID       string   `json:"sid,omitempty"`
	Subject  string   `json:"sub"`
	Username string   `json:"usr,omitempty"`
	Email    string   `json:"eml,omitempty"`
	Name     string   `json:"nam,omitempty"`
	Groups   []string `json:"grp,omitempty"`
	// Expiry is the absolute end of the session; refreshing does not
	// extend it.
	Expiry int64 `json:"exp"`
	// RefreshAt is when the session is next revalidated with the IdP
	// using RefreshToken.
	RefreshAt    int64  `json:"rat,omitempty"`
	RefreshToken string `json:"rt,omitempty"`
	// Gen counts refreshes, so copies of the same session can tell which
	// is newer.
	Gen int `json:"gen,omitempty"`
	// IssuedAt is when the proxy created the session at sign-in (Unix
	// milliseconds). Revocations invalidate sessions issued before them.
	IssuedAt int64 `json:"iat,omitempty"`
	// AuthTime is when the user authenticated at the IdP (Unix seconds).
	AuthTime int64 `json:"at,omitempty"`
	// MFA records whether the sign-in included multi-factor authentication.
	MFA bool `json:"mfa,omitempty"`
}

// Valid reports whether the session has not expired.
func (s *Session) Valid(now time.Time) bool {
	return now.Unix() < s.Expiry
}

// Display returns the most human-friendly identifier available.
func (s *Session) Display() string {
	for _, v := range []string{s.Name, s.Email, s.Username} {
		if v != "" {
			return v
		}
	}
	return s.Subject
}

// Codec seals values with AES-256-GCM. The cookie name is bound as
// additional data so a value cannot be replayed under another cookie.
type Codec struct {
	aead cipher.AEAD
}

// DeriveKey derives a 32-byte key for one purpose from secret, so keys for
// different uses are independent.
func DeriveKey(secret, purpose string) ([]byte, error) {
	return hkdf.Key(sha256.New, []byte(secret), nil, "sidegate "+purpose, 32)
}

// NewCodec creates a codec with a key derived for purpose.
func NewCodec(secret, purpose string) (*Codec, error) {
	key, err := DeriveKey(secret, purpose)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Codec{aead: aead}, nil
}

func (c *Codec) Seal(name string, v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, c.aead.NonceSize())
	rand.Read(nonce)
	sealed := c.aead.Seal(nonce, nonce, plain, []byte(name))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

var ErrInvalid = errors.New("invalid sealed value")

func (c *Codec) Open(name, value string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < c.aead.NonceSize() {
		return ErrInvalid
	}
	n := c.aead.NonceSize()
	plain, err := c.aead.Open(nil, raw[:n], raw[n:], []byte(name))
	if err != nil {
		return ErrInvalid
	}
	return json.Unmarshal(plain, v)
}
