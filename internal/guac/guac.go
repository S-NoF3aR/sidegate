// SPDX-License-Identifier: AGPL-3.0-only

// Package guac implements the parts of the Guacamole protocol the proxy
// needs to sit between a browser client and guacd: parsing instructions and
// the connection handshake.
//
// An instruction is a list of elements "LENGTH.VALUE" separated by "," and
// terminated by ";", where LENGTH counts Unicode code points. The first
// element is the opcode.
package guac

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxInstruction bounds a single instruction, protecting against memory
// exhaustion by a misbehaving peer.
const MaxInstruction = 8 << 20

// InternalOpcode marks tunnel-internal instructions (e.g. pings) that are
// handled by the tunnel and never forwarded to guacd.
const InternalOpcode = ""

var ErrMalformed = errors.New("malformed guacamole instruction")

type Instruction struct {
	Opcode string
	Args   []string
}

func New(opcode string, args ...string) Instruction {
	return Instruction{Opcode: opcode, Args: args}
}

// String encodes the instruction in wire format.
func (in Instruction) String() string {
	var b strings.Builder
	write := func(v string) {
		b.WriteString(strconv.Itoa(utf8.RuneCountInString(v)))
		b.WriteByte('.')
		b.WriteString(v)
	}
	write(in.Opcode)
	for _, a := range in.Args {
		b.WriteByte(',')
		write(a)
	}
	b.WriteByte(';')
	return b.String()
}

// Reader reads complete instructions from a stream.
type Reader struct {
	r *bufio.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReaderSize(r, 64<<10)}
}

// Buffered reports how many bytes can be read without blocking.
func (r *Reader) Buffered() int { return r.r.Buffered() }

// ReadRaw returns the next instruction in wire format, including its
// terminating ";".
func (r *Reader) ReadRaw() (string, error) {
	var b strings.Builder
	for {
		// Element length.
		n := 0
		digits := 0
		for {
			c, err := r.r.ReadByte()
			if err != nil {
				return "", err
			}
			b.WriteByte(c)
			if c == '.' {
				break
			}
			if c < '0' || c > '9' || digits > 9 {
				return "", ErrMalformed
			}
			n = n*10 + int(c-'0')
			digits++
		}
		if digits == 0 || b.Len()+n > MaxInstruction {
			return "", ErrMalformed
		}
		// Element value: n code points.
		for range n {
			c, _, err := r.r.ReadRune()
			if err != nil {
				return "", err
			}
			b.WriteRune(c)
		}
		// Separator or terminator.
		c, err := r.r.ReadByte()
		if err != nil {
			return "", err
		}
		b.WriteByte(c)
		switch c {
		case ';':
			return b.String(), nil
		case ',':
		default:
			return "", ErrMalformed
		}
	}
}

// Read returns the next parsed instruction.
func (r *Reader) Read() (Instruction, error) {
	raw, err := r.ReadRaw()
	if err != nil {
		return Instruction{}, err
	}
	return Parse(raw)
}

// Parse decodes one instruction in wire format.
func Parse(raw string) (Instruction, error) {
	elems, rest, err := parseElements(raw)
	if err != nil || rest != "" || len(elems) == 0 {
		return Instruction{}, ErrMalformed
	}
	return Instruction{Opcode: elems[0], Args: elems[1:]}, nil
}

// Split splits a buffer of complete instructions (as sent by the browser
// client in one WebSocket message) into raw instructions.
func Split(data string) ([]string, error) {
	var out []string
	for data != "" {
		_, rest, err := parseElements(data)
		if err != nil {
			return nil, err
		}
		out = append(out, data[:len(data)-len(rest)])
		data = rest
	}
	return out, nil
}

// parseElements parses one instruction from the start of s.
func parseElements(s string) (elems []string, rest string, err error) {
	for {
		dot := strings.IndexByte(s, '.')
		if dot <= 0 || dot > 10 {
			return nil, "", ErrMalformed
		}
		n, err := strconv.Atoi(s[:dot])
		if err != nil || n < 0 {
			return nil, "", ErrMalformed
		}
		s = s[dot+1:]
		// Advance n code points.
		i := 0
		for range n {
			if i >= len(s) {
				return nil, "", ErrMalformed
			}
			_, size := utf8.DecodeRuneInString(s[i:])
			i += size
		}
		if i >= len(s) {
			return nil, "", ErrMalformed
		}
		elems = append(elems, s[:i])
		term := s[i]
		s = s[i+1:]
		switch term {
		case ';':
			return elems, s, nil
		case ',':
		default:
			return nil, "", ErrMalformed
		}
	}
}

// Error is an "error" instruction received from guacd.
type Error struct {
	Message string
	Code    string
}

func (e *Error) Error() string { return fmt.Sprintf("guacd: %s (status %s)", e.Message, e.Code) }

// Handshake configures a new connection on a fresh guacd connection and
// returns the connection ID guacd assigned. params maps the protocol's
// argument names to values; arguments guacd asks for that are missing are
// sent empty.
func Handshake(w io.Writer, r *Reader, protocol string, params map[string]string, width, height, dpi int, timezone, name string) (string, error) {
	send := func(in Instruction) error {
		_, err := io.WriteString(w, in.String())
		return err
	}
	if err := send(New("select", protocol)); err != nil {
		return "", err
	}
	args, err := r.Read()
	if err != nil {
		return "", fmt.Errorf("read args: %w", err)
	}
	if args.Opcode == "error" {
		return "", errorFrom(args)
	}
	if args.Opcode != "args" {
		return "", fmt.Errorf("expected args, got %q", args.Opcode)
	}

	steps := []Instruction{
		New("size", strconv.Itoa(width), strconv.Itoa(height), strconv.Itoa(dpi)),
		New("audio", "audio/L8", "audio/L16"),
		New("video"),
		New("image", "image/jpeg", "image/png", "image/webp"),
	}
	if timezone != "" {
		steps = append(steps, New("timezone", timezone))
	}
	if name != "" {
		steps = append(steps, New("name", name))
	}
	// Protocol 1.1+ starts the argument list with the version; answering
	// with it enables features like prompting for credentials ("required").
	values := make([]string, len(args.Args))
	for i, a := range args.Args {
		if i == 0 && strings.HasPrefix(a, "VERSION_") {
			values[i] = a
			continue
		}
		values[i] = params[a]
	}
	steps = append(steps, New("connect", values...))
	for _, in := range steps {
		if err := send(in); err != nil {
			return "", err
		}
	}

	ready, err := r.Read()
	if err != nil {
		return "", fmt.Errorf("read ready: %w", err)
	}
	if ready.Opcode == "error" {
		return "", errorFrom(ready)
	}
	if ready.Opcode != "ready" || len(ready.Args) == 0 {
		return "", fmt.Errorf("expected ready, got %q", ready.Opcode)
	}
	return ready.Args[0], nil
}

func errorFrom(in Instruction) error {
	e := &Error{}
	if len(in.Args) > 0 {
		e.Message = in.Args[0]
	}
	if len(in.Args) > 1 {
		e.Code = in.Args[1]
	}
	return e
}
