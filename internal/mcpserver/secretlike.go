package mcpserver

import (
	"math"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Secret-like content is never returned to the model by receive, even when
// plaintext is allowed (spec §9). The check is deliberately conservative: a
// false positive only means the content goes to a file or the local store
// instead of the transcript. Text is NFKC-normalised, stripped of invisible
// characters and folded from common homoglyphs before matching, and tokens
// wrapped across lines are also checked joined.

var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"OpenAI/Anthropic-style key (sk-)", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}`)},
	{"Stripe-style key", regexp.MustCompile(`(?i)\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}`)},
	{"webhook signing secret (whsec_)", regexp.MustCompile(`\bwhsec_[A-Za-z0-9+/=]{8,}`)},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{16,}`)},
	{"GitHub fine-grained token (github_pat_)", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{16,}`)},
	{"GitLab token", regexp.MustCompile(`\bgl(?:pat|dt|ptt|rt|cbt|oas)-[A-Za-z0-9_-]{16,}`)},
	{"AWS access key id", regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{12,}`)},
	{"Slack token", regexp.MustCompile(`\bxox[abeprs]-[A-Za-z0-9-]{8,}`)},
	{"Slack app token", regexp.MustCompile(`\bxapp-[0-9]-[A-Za-z0-9-]{8,}`)},
	{"Google API key", regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{30,}`)},
	{"Google OAuth token", regexp.MustCompile(`\bya29\.[A-Za-z0-9_-]{20,}`)},
	{"npm token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{30,}`)},
	{"PyPI token", regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{30,}`)},
	{"Hugging Face token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`)},
	{"SendGrid key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`)},
	{"Shopify token", regexp.MustCompile(`\bshp(?:at|ca|pa|ss)_[A-Fa-f0-9]{20,}`)},
	{"DigitalOcean token", regexp.MustCompile(`\bdo[opr]_v1_[a-f0-9]{40,}`)},
	{"Twilio key", regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)},
	{"Azure storage key", regexp.MustCompile(`(?i)AccountKey=[A-Za-z0-9+/=]{20,}`)},
	{"PasteVault API token", regexp.MustCompile(`\bpv_pat_[a-z2-7]{8,}`)},
	{"private key block", regexp.MustCompile(`(?i)-----\s*BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?\s*-----`)},
	{"JSON Web Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.`)},
	{"credentials in a URL", regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`)},
	{"Authorization header", regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{16,}=*`)},
	// Assignments to secret-looking keys in dotenv, shell, YAML, JSON, INI
	// or TOML: password=…, "api_key": "…", export TOKEN = …, secret:\t….
	{"secret-named key with a value", regexp.MustCompile(`(?im)["']?[A-Za-z0-9_.-]*(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential|auth)[A-Za-z0-9_.-]*["']?[ \t]*[:=][ \t]*["']?[^\s"',}{]{4,}`)},
	// dotenv-shaped assignments at a line start: KEY=value, export KEY=value,
	// and upper-case KEY = value.
	{"dotenv-style KEY=value line", regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?(?:[A-Za-z_][A-Za-z0-9_]*=[^\s=]|[A-Z][A-Z0-9_]*[ \t]*=[ \t]*[^\s=])`)},
}

// tokenRun matches candidate tokens for the entropy check: long runs of
// characters that keys, tokens and base64/hex encodings are made of.
var tokenRun = regexp.MustCompile(`[A-Za-z0-9+/=_\-.~]{20,}`)

// wrappedToken joins token characters split by a line break (and the
// indentation or quotes around it), so a key wrapped across lines is seen
// whole.
var wrappedToken = regexp.MustCompile(`([A-Za-z0-9+/=_-])["']?[ \t]*\r?\n[ \t]*["']?[ \t]*(?:\+[ \t]*["']?)?([A-Za-z0-9+/=_-])`)

const (
	minHighEntropyLength = 20
	highEntropyBits      = 3.5
)

// SecretLikeReason returns why text looks like it contains a secret, or ""
// when it does not.
func SecretLikeReason(text string) string {
	normalized := normalizeForMatching(text)
	for _, candidate := range []string{normalized, wrappedToken.ReplaceAllString(normalized, "$1$2")} {
		if reason := secretLikeReason(candidate); reason != "" {
			return reason
		}
	}
	return ""
}

func secretLikeReason(text string) string {
	for _, candidate := range secretPatterns {
		if candidate.pattern.MatchString(text) {
			return candidate.name
		}
	}
	for _, token := range tokenRun.FindAllString(text, -1) {
		if looksLikeRandomToken(token) {
			return "a long high-entropy token"
		}
	}

	return ""
}

// IsSecretLike reports whether text looks like it contains a secret.
func IsSecretLike(text string) bool {
	return SecretLikeReason(text) != ""
}

// homoglyphs maps letters that look like ASCII letters (Cyrillic, Greek,
// Latin small capitals) to them; NFKC already folds full-width and
// mathematical forms.
var homoglyphs = strings.NewReplacer(
	"а", "a", "в", "B", "е", "e", "к", "k", "м", "M", "н", "H", "о", "o", "р", "p", "с", "c", "т", "T", "у", "y", "х", "x",
	"ѕ", "s", "і", "i", "г", "r", "ь", "b", "п", "n", "ј", "j", "ԁ", "d", "ԛ", "q", "ԝ", "w", "ɡ", "g", "ɑ", "a", "ο", "o", "ν", "v", "ι", "i", "κ", "k",
	"А", "A", "В", "B", "Е", "E", "К", "K", "М", "M", "Н", "H", "О", "O", "Р", "P", "С", "C", "Т", "T", "У", "Y", "Х", "X",
	"Ѕ", "S", "І", "I", "Ј", "J", "Ԛ", "Q", "Ԝ", "W",
	"Α", "A", "Β", "B", "Ε", "E", "Ζ", "Z", "Η", "H", "Ι", "I", "Κ", "K", "Μ", "M", "Ν", "N", "Ο", "O", "Ρ", "P", "Τ", "T", "Υ", "Y", "Χ", "X",
	"‐", "-", "‑", "-", "‒", "-", "–", "-", "—", "-", "−", "-",
)

// normalizeForMatching applies NFKC, drops invisible format characters
// (zero-width spaces and joiners, soft hyphens, BOMs, bidi controls) and
// folds homoglyphs.
func normalizeForMatching(text string) string {
	normalized := norm.NFKC.String(text)
	normalized = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, normalized)
	return homoglyphs.Replace(normalized)
}

// looksLikeRandomToken: at least 20 characters, letters and digits mixed,
// and more than 3.5 bits of Shannon entropy per character. Requiring both
// letters and digits keeps ordinary words, paths and host names out.
func looksLikeRandomToken(token string) bool {
	token = strings.Trim(token, ".-_~/=")
	if len(token) < minHighEntropyLength {
		return false
	}
	hasLetter, hasDigit := false, false
	for _, r := range token {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return false
	}

	return shannonEntropy(token) > highEntropyBits
}

func shannonEntropy(value string) float64 {
	counts := map[rune]int{}
	total := 0
	for _, r := range value {
		counts[r]++
		total++
	}
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}

	return entropy
}
