// Package envmask hides secret values in a command's output stream
// (pastevault run, spec §5.5).
//
// Every occurrence of a value, or of a common encoding of it, is replaced
// with "[masked:NAME]". The encodings are base64 (standard and URL, padded,
// unpadded, and embedded in a longer base64 stream at byte offsets 0, 1 and
// 2), hex (lower and upper case), URL query and path escaping, and JSON
// string escaping.
//
// Masking protects transcripts (terminal scrollback, CI logs, an agent's
// context window) from accidental disclosure. It is NOT a security boundary:
// a program can always transform a secret in a way the masker does not
// recognise (other encodings, line-wrapped base64, splitting it up, writing
// it to a file or the network).
package envmask

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
)

// MinSecretLength is the shortest value that is masked. Shorter values would
// mask ordinary output (and reveal the secret by where the masks land).
const MinSecretLength = 6

// Secret is a named value to mask.
type Secret struct {
	Name  string
	Value []byte
}

// Replacement is the text a masked occurrence of secret name becomes.
func Replacement(name string) string {
	return "[masked:" + name + "]"
}

type pattern struct {
	text        []byte
	replacement []byte
}

// Masker holds the patterns for a set of secrets. It is safe for concurrent
// use; each Writer has its own streaming state.
type Masker struct {
	patterns []pattern
	// byFirst indexes patterns by their first byte, longest first.
	byFirst [256][]int
}

// New builds the pattern set. Values shorter than MinSecretLength (and empty
// ones) are not masked; each such secret yields a warning naming it (never
// its value).
func New(secrets []Secret) (*Masker, []string) {
	m := &Masker{}
	var warnings []string
	seen := map[string]bool{}

	for _, secret := range secrets {
		switch {
		case len(secret.Value) == 0:
			warnings = append(warnings, fmt.Sprintf("%s is empty; there is nothing to mask", secret.Name))
			continue
		case len(secret.Value) < MinSecretLength:
			warnings = append(warnings, fmt.Sprintf("%s is shorter than %d bytes and is not masked in the output", secret.Name, MinSecretLength))
			continue
		}

		replacement := []byte(Replacement(secret.Name))
		for _, variant := range variants(secret.Value) {
			if len(variant) < MinSecretLength || seen[variant] {
				continue
			}
			seen[variant] = true
			m.patterns = append(m.patterns, pattern{text: []byte(variant), replacement: replacement})
		}
	}

	for index, p := range m.patterns {
		first := p.text[0]
		m.byFirst[first] = append(m.byFirst[first], index)
	}
	for first := range m.byFirst {
		list := m.byFirst[first]
		sort.SliceStable(list, func(i, j int) bool {
			return len(m.patterns[list[i]].text) > len(m.patterns[list[j]].text)
		})
	}

	return m, warnings
}

// variants lists the forms of v that are masked. A multi-line value is
// also masked with its line endings normalised (LF and CRLF) and line by
// line (each line of at least MinSecretLength non-blank bytes), so a PEM key
// printed with CRLF or with a prefix on every line is still caught.
func variants(v []byte) []string {
	forms := [][]byte{v}
	multiLine := bytes.ContainsAny(v, "\r\n")
	var lf []byte
	if multiLine {
		lf = bytes.ReplaceAll(v, []byte("\r\n"), []byte("\n"))
		forms = append(forms, lf, bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n")))
	}

	var out []string
	for _, form := range forms {
		out = append(out, encodings(form)...)
	}
	if multiLine {
		for _, line := range bytes.Split(lf, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) >= MinSecretLength {
				out = append(out, string(line))
			}
		}
	}

	return out
}

// encodings are the encoded forms of one value.
func encodings(v []byte) []string {
	out := []string{
		string(v),
		base64.StdEncoding.EncodeToString(v),
		base64.RawStdEncoding.EncodeToString(v),
		base64.URLEncoding.EncodeToString(v),
		base64.RawURLEncoding.EncodeToString(v),
		hex.EncodeToString(v),
		strings.ToUpper(hex.EncodeToString(v)),
	}

	// URL encodings, each with upper and lower case hex digits:
	// Go's query (= Python quote_plus) and path escaping, strict RFC 3986
	// (curl --data-urlencode, Python quote(safe="")), JavaScript's
	// encodeURIComponent, Python's quote() (keeps "/"), and the userinfo
	// part of a URL (a password in postgres://user:PASSWORD@host) as Go and
	// WHATWG (browsers, Node) escape it.
	percent := []string{
		url.QueryEscape(string(v)),
		url.PathEscape(string(v)),
		percentEncode(v, isUnreserved),
		percentEncode(v, func(c byte) bool { return isUnreserved(c) || strings.IndexByte("!*'()", c) >= 0 }),
		percentEncode(v, func(c byte) bool { return isUnreserved(c) || c == '/' }),
		strings.TrimPrefix(url.UserPassword("u", string(v)).String(), "u:"),
		url.User(string(v)).String(),
		percentEncode(v, func(c byte) bool { return c > 0x20 && c < 0x7f && strings.IndexByte("\"#<>?`{}/:;=@[\\]^|", c) < 0 }),
	}
	for _, encoded := range percent {
		out = append(out, encoded, lowerPercentHex(encoded))
	}

	out = append(out, jsonVariants(v)...)
	for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for offset := 0; offset <= 2; offset++ {
			out = append(out, embeddedBase64(encoding, v, offset))
		}
	}

	return out
}

func isUnreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

// percentEncode escapes every byte that keep rejects as %XX (upper case).
func percentEncode(v []byte, keep func(byte) bool) string {
	const digits = "0123456789ABCDEF"
	var builder strings.Builder
	for _, c := range v {
		if keep(c) {
			builder.WriteByte(c)
			continue
		}
		builder.WriteByte('%')
		builder.WriteByte(digits[c>>4])
		builder.WriteByte(digits[c&15])
	}

	return builder.String()
}

// lowerPercentHex lower-cases the hex digits of %XX escapes.
func lowerPercentHex(s string) string {
	encoded := []byte(s)
	for i := 0; i+2 < len(encoded); i++ {
		if encoded[i] == '%' {
			encoded[i+1] = toLowerHex(encoded[i+1])
			encoded[i+2] = toLowerHex(encoded[i+2])
		}
	}

	return string(encoded)
}

func toLowerHex(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + 'a' - 'A'
	}
	return c
}

// embeddedBase64 is the part of a base64 stream that depends only on v when
// v starts `offset` bytes past a 3-byte boundary and more data may follow:
// encode 0x00×offset || v, drop the first ceil(4·offset/3) characters (they
// mix in the preceding bytes) and the last one when it is partial (it mixes
// in the following bytes).
func embeddedBase64(encoding *base64.Encoding, v []byte, offset int) string {
	data := append(make([]byte, offset), v...)
	encoded := encoding.EncodeToString(data)
	encoded = encoded[(4*offset+2)/3:]
	if len(data)%3 != 0 && len(encoded) > 0 {
		encoded = encoded[:len(encoded)-1]
	}

	return encoded
}

// jsonVariants are v's JSON string contents (without quotes) as Go escapes
// them with and without HTML escaping, and with every non-ASCII rune as
// \uXXXX (Python's default).
func jsonVariants(v []byte) []string {
	var out []string

	if encoded, err := json.Marshal(string(v)); err == nil {
		out = append(out, string(encoded[1:len(encoded)-1]))
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(string(v)); err != nil {
		return out
	}
	plain := strings.TrimSuffix(buffer.String(), "\n")
	plain = plain[1 : len(plain)-1]
	out = append(out, plain)

	var ascii strings.Builder
	for _, r := range plain {
		switch {
		case r < 0x80:
			ascii.WriteRune(r)
		case r > 0xFFFF:
			high, low := utf16.EncodeRune(r)
			fmt.Fprintf(&ascii, `\u%04x\u%04x`, high, low)
		default:
			fmt.Fprintf(&ascii, `\u%04x`, r)
		}
	}
	out = append(out, ascii.String())

	return out
}

// Enabled reports whether there is anything to mask.
func (m *Masker) Enabled() bool {
	return m != nil && len(m.patterns) > 0
}

// scan masks buf into out. Unless final, it stops at the first position where
// a pattern longer than any complete match there could still match once more
// data arrives, and returns how much of buf it consumed (the rest must be
// held back). With final, all of buf is consumed.
func (m *Masker) scan(buf []byte, final bool, out []byte) ([]byte, int) {
	i := 0
	for i < len(buf) {
		candidates := m.byFirst[buf[i]]
		if len(candidates) == 0 {
			out = append(out, buf[i])
			i++
			continue
		}

		rest := buf[i:]
		match := -1
		for _, index := range candidates {
			text := m.patterns[index].text
			if len(text) > len(rest) {
				// Longest first: a pending pattern beats every complete one.
				if !final && bytes.HasPrefix(text, rest) {
					return out, i
				}
				continue
			}
			if bytes.HasPrefix(rest, text) {
				match = index
				break
			}
		}

		if match < 0 {
			out = append(out, buf[i])
			i++
			continue
		}
		out = append(out, m.patterns[match].replacement...)
		i += len(m.patterns[match].text)
	}

	return out, len(buf)
}

// MaskString masks a complete string.
func (m *Masker) MaskString(s string) string {
	if !m.Enabled() {
		return s
	}
	out, _ := m.scan([]byte(s), true, nil)
	return string(out)
}

// ErrClosed is returned by Write after Close.
var ErrClosed = errors.New("envmask: write after close")

// Writer masks a stream written to it and forwards it to an underlying
// writer. Bytes that could be the start of a secret are held back until it
// is clear whether they are; Close flushes them. There is no flush timer, so
// a partial secret is never emitted early.
type Writer struct {
	m      *Masker
	w      io.Writer
	mu     sync.Mutex
	held   []byte
	out    []byte
	closed bool
}

// Wrap returns a masking writer that forwards to w.
func (m *Masker) Wrap(w io.Writer) *Writer {
	return &Writer{m: m, w: w}
}

// Write masks p and forwards everything that can no longer be part of a
// match. It reports len(p) on success, even when some bytes are held back.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, ErrClosed
	}
	if !w.m.Enabled() {
		return w.w.Write(p)
	}

	buf := append(w.held, p...)
	var consumed int
	w.out, consumed = w.m.scan(buf, false, w.out[:0])
	w.held = append(w.held[:0], buf[consumed:]...)

	if len(w.out) > 0 {
		if _, err := w.w.Write(w.out); err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

// Close flushes the held bytes, masking complete matches among them. It does
// not close the underlying writer. Calling it again does nothing.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true
	if len(w.held) == 0 {
		return nil
	}

	out, _ := w.m.scan(w.held, true, w.out[:0])
	w.held = nil
	_, err := w.w.Write(out)
	return err
}
