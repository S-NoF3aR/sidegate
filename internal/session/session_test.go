// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"strings"
	"testing"
)

func TestCodec(t *testing.T) {
	secret := strings.Repeat("x", 32)
	c, _ := NewCodec(secret, "session")
	in := Session{Subject: "s", Groups: []string{"g"}, Expiry: 42}
	val, err := c.Seal("cookie", in)
	if err != nil {
		t.Fatal(err)
	}
	var out Session
	if err := c.Open("cookie", val, &out); err != nil || out.Subject != "s" || out.Groups[0] != "g" {
		t.Fatalf("roundtrip: %v %+v", err, out)
	}
	if c.Open("other-cookie", val, &out) == nil {
		t.Error("value accepted under a different cookie name")
	}
	other, _ := NewCodec(secret, "oauth-state")
	if other.Open("cookie", val, &out) == nil {
		t.Error("value accepted by codec with a different purpose")
	}
	tampered := val[:len(val)-2] + "AA"
	if c.Open("cookie", tampered, &out) == nil {
		t.Error("tampered value accepted")
	}
}
