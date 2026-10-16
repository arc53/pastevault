package envmask

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"net/url"
	"strings"
	"testing"
)

func mustMasker(t testing.TB, secrets ...Secret) *Masker {
	t.Helper()
	m, warnings := New(secrets)
	if len(warnings) > 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	return m
}

func stream(t testing.TB, m *Masker, chunks [][]byte) string {
	t.Helper()
	var out bytes.Buffer
	w := m.Wrap(&out)
	for _, chunk := range chunks {
		n, err := w.Write(chunk)
		if err != nil || n != len(chunk) {
			t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(chunk))
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestEveryVariantIsMasked(t *testing.T) {
	values := []string{
		"s3cr3t-value",           // len 12, %3 == 0
		"s3cr3t-value1",          // %3 == 1
		"s3cr3t-value12",         // %3 == 2
		"p@ss w/rd&<x>?=+é😀",     // escaping-heavy
		"\xff\xfe\x00binary\x01", // binary
	}
	for _, value := range values {
		v := []byte(value)
		m := mustMasker(t, Secret{Name: "TOKEN", Value: v})

		var jsonHTML, jsonPlain bytes.Buffer
		encoded, _ := json.Marshal(value)
		jsonHTML.Write(encoded[1 : len(encoded)-1])
		encoder := json.NewEncoder(&jsonPlain)
		encoder.SetEscapeHTML(false)
		_ = encoder.Encode(value)
		plain := strings.TrimSuffix(jsonPlain.String(), "\n")

		forms := map[string]string{
			"raw":           value,
			"std padded":    base64.StdEncoding.EncodeToString(v),
			"std unpadded":  base64.RawStdEncoding.EncodeToString(v),
			"url padded":    base64.URLEncoding.EncodeToString(v),
			"url unpadded":  base64.RawURLEncoding.EncodeToString(v),
			"hex lower":     hex.EncodeToString(v),
			"hex upper":     strings.ToUpper(hex.EncodeToString(v)),
			"query escape":  url.QueryEscape(value),
			"path escape":   url.PathEscape(value),
			"json html":     jsonHTML.String(),
			"json plain":    plain[1 : len(plain)-1],
			"echo | base64": base64.StdEncoding.EncodeToString(append(append([]byte{}, v...), '\n')),
		}
		// Embedded in a longer base64 stream at every alignment, both
		// alphabets, with data before and after.
		for offset := 0; offset <= 2; offset++ {
			data := append(append([]byte("xyz"[:offset]), v...), "\n tail"...)
			forms["std offset "+string(rune('0'+offset))] = base64.StdEncoding.EncodeToString(data)
			forms["url offset "+string(rune('0'+offset))] = base64.URLEncoding.EncodeToString(data)
		}

		for label, form := range forms {
			input := "before " + form + " after"
			got := m.MaskString(input)
			if !strings.Contains(got, "[masked:TOKEN]") {
				t.Errorf("%q %s: not masked: %q", value, label, got)
			}
			if strings.Contains(got, value) {
				t.Errorf("%q %s: raw value leaked: %q", value, label, got)
			}
			for _, p := range m.patterns {
				if bytes.Contains([]byte(got), p.text) {
					t.Errorf("%q %s: pattern %q still in output %q", value, label, p.text, got)
				}
			}
			if streamed := stream(t, m, [][]byte{[]byte(input)}); streamed != got {
				t.Errorf("%q %s: stream %q != one-shot %q", value, label, streamed, got)
			}
		}
	}
}

func TestEmbeddedBase64Pattern(t *testing.T) {
	v := []byte("abcdefgh")
	for offset := 0; offset <= 2; offset++ {
		for _, prefix := range [][]byte{{0, 0, 0}, {0xff, 0xff, 0xff}, []byte("Q!z")} {
			for _, suffix := range [][]byte{nil, {0}, {0xff, 0x01}, []byte("\n")} {
				data := append(append(append([]byte{}, prefix[:offset]...), v...), suffix...)
				for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
					pattern := embeddedBase64(base64.RawStdEncoding, v, offset)
					if enc == base64.URLEncoding || enc == base64.RawURLEncoding {
						pattern = embeddedBase64(base64.RawURLEncoding, v, offset)
					}
					if !strings.Contains(enc.EncodeToString(data), pattern) {
						t.Errorf("offset %d prefix %x suffix %x: %q not in %q", offset, prefix[:offset], suffix, pattern, enc.EncodeToString(data))
					}
				}
			}
		}
	}
}

func TestEchoPipeBase64(t *testing.T) {
	for _, value := range []string{"abcdefghijkl", "abcdefghijklm", "abcdefghijklmn"} {
		m := mustMasker(t, Secret{Name: "X", Value: []byte(value)})
		output := value + "\n" + base64.StdEncoding.EncodeToString([]byte(value+"\n")) + "\n"
		got := m.MaskString(output)
		if strings.Count(got, "[masked:X]") != 2 {
			t.Errorf("len %d: %q", len(value), got)
		}
	}
}

func TestShortValuesWarnAndAreNotMasked(t *testing.T) {
	m, warnings := New([]Secret{
		{Name: "SHORT", Value: []byte("abc12")},
		{Name: "EMPTY", Value: nil},
		{Name: "LONG", Value: []byte("long-enough")},
	})
	if len(warnings) != 2 {
		t.Fatalf("warnings = %v", warnings)
	}
	for _, warning := range warnings {
		if strings.Contains(warning, "abc12") {
			t.Errorf("warning leaks the value: %q", warning)
		}
	}
	if !strings.Contains(warnings[0], "SHORT") || !strings.Contains(warnings[1], "EMPTY") {
		t.Errorf("warnings don't name the secrets: %v", warnings)
	}
	if got := m.MaskString("abc12 long-enough"); got != "abc12 [masked:LONG]" {
		t.Errorf("got %q", got)
	}

	none, _ := New([]Secret{{Name: "S", Value: []byte("12345")}})
	if none.Enabled() {
		t.Error("masker with only short values should be disabled")
	}
	var out bytes.Buffer
	w := none.Wrap(&out)
	if _, err := w.Write([]byte("12345")); err != nil || out.String() != "12345" {
		t.Errorf("disabled masker should pass through: %q %v", out.String(), err)
	}
}

func TestLeftmostLongest(t *testing.T) {
	m := mustMasker(t,
		Secret{Name: "SHORT", Value: []byte("secret")},
		Secret{Name: "LONG", Value: []byte("secret-extended")},
		Secret{Name: "OTHER", Value: []byte("tended-xyz")},
	)
	cases := map[string]string{
		"secret":                  "[masked:SHORT]",
		"secret-extended":         "[masked:LONG]",
		"secret-exten":            "[masked:SHORT]-exten",
		"xsecret-extended-xyz":    "x[masked:LONG]-xyz",
		"secret-extended-xyz":     "[masked:LONG]-xyz",
		"secretsecret":            "[masked:SHORT][masked:SHORT]",
		"secret-extended-xyzsecr": "[masked:LONG]-xyzsecr",
		"exsecret-tended-xyz":     "ex[masked:SHORT]-[masked:OTHER]",
	}
	for input, want := range cases {
		if got := m.MaskString(input); got != want {
			t.Errorf("MaskString(%q) = %q, want %q", input, got, want)
		}
		if got := stream(t, m, splitEvery(input)); got != want {
			t.Errorf("stream(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestMultipleSecretsAdjacencyAndEdges(t *testing.T) {
	m := mustMasker(t,
		Secret{Name: "A", Value: []byte("alpha-secret")},
		Secret{Name: "B", Value: []byte("bravo-secret")},
	)
	cases := map[string]string{
		"alpha-secretbravo-secret":     "[masked:A][masked:B]",
		"alpha-secret":                 "[masked:A]",
		"x alpha-secret":               "x [masked:A]",
		"alpha-secret x":               "[masked:A] x",
		"bravo-secret\nalpha-secret\n": "[masked:B]\n[masked:A]\n",
		"alpha-secre":                  "alpha-secre",
		"":                             "",
	}
	for input, want := range cases {
		if got := m.MaskString(input); got != want {
			t.Errorf("MaskString(%q) = %q, want %q", input, got, want)
		}
	}
}

func splitEvery(s string) [][]byte {
	chunks := make([][]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		chunks = append(chunks, []byte{s[i]})
	}
	return chunks
}

func TestEveryChunkSplitPoint(t *testing.T) {
	m := mustMasker(t,
		Secret{Name: "A", Value: []byte("alpha-secret-1")},
		Secret{Name: "B", Value: []byte("alpha-secret-1-and-more")},
		Secret{Name: "C", Value: []byte("p@ss w/rd&<x>")},
	)
	inputs := []string{
		"start alpha-secret-1 middle alpha-secret-1-and-more end",
		"alpha-secret-1alpha-secret-1-and-mor",
		base64.StdEncoding.EncodeToString([]byte("xalpha-secret-1\n")) + " " + hex.EncodeToString([]byte("p@ss w/rd&<x>")),
		"aaaaalpha-secret-alpha-secret-1-and-more" + url.QueryEscape("p@ss w/rd&<x>"),
		"no secrets here at all",
	}
	random := rand.New(rand.NewSource(1))
	for _, input := range inputs {
		want := m.MaskString(input)
		for split := 0; split <= len(input); split++ {
			if got := stream(t, m, [][]byte{[]byte(input[:split]), []byte(input[split:])}); got != want {
				t.Fatalf("split %d of %q: %q, want %q", split, input, got, want)
			}
			for second := split; second <= len(input); second++ {
				chunks := [][]byte{[]byte(input[:split]), []byte(input[split:second]), []byte(input[second:])}
				if got := stream(t, m, chunks); got != want {
					t.Fatalf("splits %d,%d of %q: %q, want %q", split, second, input, got, want)
				}
			}
		}
		if got := stream(t, m, splitEvery(input)); got != want {
			t.Fatalf("1-byte writes of %q: %q, want %q", input, got, want)
		}
		for round := 0; round < 200; round++ {
			if got := stream(t, m, randomChunks(random, []byte(input))); got != want {
				t.Fatalf("random split of %q: %q, want %q", input, got, want)
			}
		}
	}
}

func randomChunks(random *rand.Rand, data []byte) [][]byte {
	var chunks [][]byte
	for len(data) > 0 {
		n := random.Intn(len(data)) + 1
		if random.Intn(2) == 0 {
			n = random.Intn(min(len(data), 4)) + 1
		}
		chunks = append(chunks, data[:n])
		data = data[n:]
	}
	return chunks
}

// recorder keeps every Write so tests can see what reached the underlying
// writer, and when.
type recorder struct{ bytes.Buffer }

func TestNoPrefixLeakAtWriteBoundary(t *testing.T) {
	secret := "hunter2-hunter2"
	m := mustMasker(t, Secret{Name: "PW", Value: []byte(secret)})

	var out recorder
	w := m.Wrap(&out)
	for cut := 1; cut < len(secret); cut++ {
		out.Reset()
		w = m.Wrap(&out)
		if _, err := w.Write([]byte("password is " + secret[:cut])); err != nil {
			t.Fatal(err)
		}
		if out.String() != "password is " {
			t.Fatalf("cut %d: emitted %q before the secret was complete", cut, out.String())
		}
		if _, err := w.Write([]byte(secret[cut:] + "!")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if out.String() != "password is [masked:PW]!" {
			t.Fatalf("cut %d: %q", cut, out.String())
		}
	}

	// A prefix that never completes is emitted raw at Close: it isn't the
	// secret.
	out.Reset()
	w = m.Wrap(&out)
	_, _ = w.Write([]byte("hunter2-hun"))
	if out.Len() != 0 {
		t.Fatalf("prefix leaked: %q", out.String())
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "hunter2-hun" {
		t.Fatalf("Close emitted %q", out.String())
	}
	if err := w.Close(); err != nil {
		t.Fatal("second Close should be a no-op")
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}

	// A prefix that turns into something else is released as soon as the
	// mismatch arrives, without waiting for Close.
	out.Reset()
	w = m.Wrap(&out)
	_, _ = w.Write([]byte("hunter2-"))
	_, _ = w.Write([]byte("x"))
	if out.String() != "hunter2-x" {
		t.Fatalf("mismatch not released: %q", out.String())
	}
}

func TestHeldBytesAreBounded(t *testing.T) {
	m := mustMasker(t, Secret{Name: "A", Value: []byte("aaaaaaaaab")})
	w := m.Wrap(&bytes.Buffer{})
	maxLen := 0
	for _, p := range m.patterns {
		maxLen = max(maxLen, len(p.text))
	}
	for i := 0; i < 1000; i++ {
		_, _ = w.Write([]byte("a"))
		if len(w.held) >= maxLen {
			t.Fatalf("held %d bytes, max pattern %d", len(w.held), maxLen)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestWriteErrorsPropagate(t *testing.T) {
	m := mustMasker(t, Secret{Name: "A", Value: []byte("abcdefgh")})
	w := m.Wrap(failingWriter{})
	if _, err := w.Write([]byte("hello ")); err == nil {
		t.Fatal("expected the underlying error")
	}
}

func TestWriteDoesNotRetainInput(t *testing.T) {
	m := mustMasker(t, Secret{Name: "A", Value: []byte("abcdefgh")})
	var out bytes.Buffer
	w := m.Wrap(&out)
	buf := []byte("xx abcd")
	_, _ = w.Write(buf)
	copy(buf, "ZZZZZZZ")
	_, _ = w.Write([]byte("efgh"))
	_ = w.Close()
	if out.String() != "xx [masked:A]" {
		t.Fatalf("got %q", out.String())
	}
}

var fuzzSecrets = []Secret{
	{Name: "A", Value: []byte("hunter2hunter2")},
	{Name: "B", Value: []byte("s3cr3t-T0K3N_value")},
	{Name: "C", Value: []byte("s3cr3t-T0K")},
}

func FuzzMaskerSplits(f *testing.F) {
	f.Add([]byte("hello hunter2hunter2 world"), int64(1))
	f.Add([]byte("s3cr3t-T0K3N_valu s3cr3t-T0K3N_value"), int64(2))
	f.Add([]byte(base64.StdEncoding.EncodeToString([]byte("hunter2hunter2\n"))), int64(3))
	f.Add([]byte(hex.EncodeToString([]byte("s3cr3t-T0K3N_value"))+"s3cr3t-T0K"), int64(4))
	f.Add([]byte("aGVsbG8gaHVudGVyMmh1bnRlcjI="), int64(5))

	m, _ := New(fuzzSecrets)
	f.Fuzz(func(t *testing.T, input []byte, seed int64) {
		want := m.MaskString(string(input))
		got := stream(t, m, randomChunks(rand.New(rand.NewSource(seed)), input))
		if got != want {
			t.Fatalf("stream %q != one-shot %q", got, want)
		}
		for _, secret := range fuzzSecrets {
			if bytes.Contains([]byte(got), secret.Value) {
				t.Fatalf("raw %s in output %q", secret.Name, got)
			}
		}
	})
}
