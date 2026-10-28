// SPDX-License-Identifier: AGPL-3.0-only

package guac

import (
	"net"
	"strings"
	"testing"
)

func TestEncodeParse(t *testing.T) {
	in := New("name", "Grüße, Welt;", "", "x")
	raw := in.String()
	if raw != "4.name,12.Grüße, Welt;,0.,1.x;" {
		t.Fatalf("encoded %q", raw)
	}
	got, err := Parse(raw)
	if err != nil || got.Opcode != "name" || len(got.Args) != 3 || got.Args[0] != "Grüße, Welt;" {
		t.Fatalf("parse: %+v %v", got, err)
	}
	r := NewReader(strings.NewReader(raw + "4.sync,3.123;"))
	for _, want := range []string{raw, "4.sync,3.123;"} {
		if got, err := r.ReadRaw(); err != nil || got != want {
			t.Errorf("ReadRaw = %q %v, want %q", got, err, want)
		}
	}
	parts, err := Split("0.,4.ping,3.123;3.key,5.65307,1.1;")
	if err != nil || len(parts) != 2 || parts[1] != "3.key,5.65307,1.1;" {
		t.Errorf("Split = %q %v", parts, err)
	}
	for _, bad := range []string{"4.syn;", "x.sync;", "4.sync", "4.sync,", "4.sync!", "99999999999.a;"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) should fail", bad)
		}
		if _, err := NewReader(strings.NewReader(bad)).ReadRaw(); err == nil {
			t.Errorf("ReadRaw(%q) should fail", bad)
		}
	}
}

func TestHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	got := make(chan []Instruction, 1)
	go func() {
		defer server.Close()
		r := NewReader(server)
		var seen []Instruction
		sel, _ := r.Read()
		seen = append(seen, sel)
		server.Write([]byte(New("args", "VERSION_1_5_0", "hostname", "port", "username", "security").String()))
		for {
			in, err := r.Read()
			if err != nil {
				return
			}
			seen = append(seen, in)
			if in.Opcode == "connect" {
				break
			}
		}
		got <- seen
		server.Write([]byte(New("ready", "$abc").String()))
	}()
	id, err := Handshake(client, NewReader(client), "rdp",
		map[string]string{"hostname": "win1", "port": "3389", "security": "nla", "ignored": "x"},
		1280, 720, 96, "Europe/Zurich", "alice")
	if err != nil || id != "$abc" {
		t.Fatalf("handshake: %q %v", id, err)
	}
	seen := <-got
	if seen[0].String() != "6.select,3.rdp;" {
		t.Errorf("select = %s", seen[0])
	}
	connect := seen[len(seen)-1]
	if strings.Join(connect.Args, "|") != "VERSION_1_5_0|win1|3389||nla" {
		t.Errorf("connect args = %q", connect.Args)
	}
	var opcodes []string
	for _, in := range seen {
		opcodes = append(opcodes, in.Opcode)
	}
	if strings.Join(opcodes, ",") != "select,size,audio,video,image,timezone,name,connect" {
		t.Errorf("handshake order = %v", opcodes)
	}
}

func TestHandshakeError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		NewReader(server).Read()
		server.Write([]byte(New("error", "unsupported protocol", "515").String()))
		server.Close()
	}()
	_, err := Handshake(client, NewReader(client), "rdp", nil, 800, 600, 96, "", "")
	if e, ok := err.(*Error); !ok || e.Code != "515" {
		t.Errorf("err = %v", err)
	}
}
