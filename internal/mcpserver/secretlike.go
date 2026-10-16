package mcpserver

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// Secret-like content is never returned to the model by receive, even when
// plaintext is allowed (spec §9). The check is deliberately conservative: a
// false positive only means the content has to go to a file or the local
// store instead of the transcript.

var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"OpenAI-style key (sk-)", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}`)},
	{"Stripe-style key", regexp.MustCompile(`\b[rs]k_(?:live|test)_[A-Za-z0-9]{8,}`)},
	{"GitHub token (ghp_/gho_/ghu_/ghs_/ghr_)", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{16,}`)},
	{"GitHub fine-grained token (github_pat_)", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{16,}`)},
	{"GitLab token (glpat-)", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{16,}`)},
	{"AWS access key id (AKIA/ASIA)", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{12,}`)},
	{"Slack token (xoxb-/xoxp-)", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{8,}`)},
	{"Google API key (AIza)", regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{30,}`)},
	{"npm token (npm_)", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{30,}`)},
	{"PasteVault API token (pv_pat_)", regexp.MustCompile(`\bpv_pat_[a-z2-7]{8,}`)},
	{"private key block", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)},
	{"JSON Web Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.`)},
	{"credentials in a URL", regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`)},
	// dotenv-shaped assignments (KEY=value, export KEY=value) at a line start.
	{"dotenv-style KEY=value line", regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*=[^\s=]`)},
}

// tokenRun matches candidate tokens for the entropy check: long runs of
// characters that keys, tokens and base64/hex encodings are made of.
var tokenRun = regexp.MustCompile(`[A-Za-z0-9+/=_\-.~]{20,}`)

const (
	minHighEntropyLength = 20
	highEntropyBits      = 3.5
)

// SecretLikeReason returns why text looks like it contains a secret, or ""
// when it does not.
func SecretLikeReason(text string) string {
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
