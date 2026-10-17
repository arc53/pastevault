package pastevault

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxExpiresMinutes mirrors the server's bound for expires_in_minutes (one year).
	MaxExpiresMinutes = 525600
	// DefaultExpiresMinutes is the share lifetime when no --expires is given.
	DefaultExpiresMinutes = 24 * 60
)

var expiryPattern = regexp.MustCompile(`^(\d+)([mhd])$`)

// ParseExpiry parses an --expires value such as 15m, 2h or 7d into minutes.
// Only whole minutes, hours and days are accepted, between 1 minute and 365
// days, matching what the server allows.
func ParseExpiry(value string) (int, error) {
	match := expiryPattern.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return 0, UsageError("invalid --expires %q: use a number followed by m, h or d (for example 15m, 2h or 7d)", value)
	}

	amount, err := strconv.Atoi(match[1])
	if err != nil || amount < 1 {
		return 0, UsageError("invalid --expires %q: the amount must be at least 1", value)
	}

	unit := map[string]int{"m": 1, "h": 60, "d": 24 * 60}[match[2]]
	if amount > MaxExpiresMinutes/unit {
		return 0, UsageError("invalid --expires %q: the maximum is 365d", value)
	}

	return amount * unit, nil
}

// FormatMinutes renders minutes in the largest whole unit (90 -> "90m", 120 -> "2h").
func FormatMinutes(minutes int) string {
	switch {
	case minutes%(24*60) == 0:
		return fmt.Sprintf("%dd", minutes/(24*60))
	case minutes%60 == 0:
		return fmt.Sprintf("%dh", minutes/60)
	default:
		return fmt.Sprintf("%dm", minutes)
	}
}

// ExpiryFields is the expiry to send to the server: exactly one is non-zero.
type ExpiryFields struct {
	Minutes int
	Hours   int
}

// ResolveExpiry picks the request field for an expiry. Servers without
// expires_in_minutes (api_version < 2) only take whole hours; anything else
// fails with exit 14 instead of being rounded.
func ResolveExpiry(minutes int, capabilities CapabilitiesResponse) (ExpiryFields, error) {
	if capabilities.Features.ExpiresInMinutes {
		return ExpiryFields{Minutes: minutes}, nil
	}

	if minutes%60 != 0 {
		return ExpiryFields{}, UnsupportedError("this server only supports whole-hour expiry; use --expires %dh or update the server", (minutes+59)/60)
	}

	hours := minutes / 60
	if hours > MaxExpiresHours {
		return ExpiryFields{}, UsageError("this server allows at most %d hours of expiry", MaxExpiresHours)
	}

	return ExpiryFields{Hours: hours}, nil
}

var waitDurationPattern = regexp.MustCompile(`^(\d+)([smhd])$`)

// ParseWaitDuration parses durations for --timeout and --interval: 30s, 10m,
// 2h, 1d, or any Go duration such as 1m30s or 500ms.
func ParseWaitDuration(flagName, value string) (time.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if match := waitDurationPattern.FindStringSubmatch(trimmed); match != nil {
		amount, err := strconv.ParseInt(match[1], 10, 64)
		if err == nil {
			unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[match[2]]
			if amount > 0 && amount <= int64(366*24*time.Hour/unit) {
				return time.Duration(amount) * unit, nil
			}
		}
	}

	duration, err := time.ParseDuration(trimmed)
	if err != nil || duration <= 0 {
		return 0, UsageError("invalid %s %q: use a duration such as 30s, 10m or 2h", flagName, value)
	}

	return duration, nil
}

var sincePattern = regexp.MustCompile(`^\d{1,6}[mhd]$`)

// ValidateSince checks an audit --since value: a relative 15m/24h/7d or an
// RFC 3339 timestamp, as the server accepts.
func ValidateSince(value string) error {
	if sincePattern.MatchString(value) {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, value); err == nil {
		return nil
	}

	return UsageError("invalid --since %q: use a duration such as 24h or 7d, or an RFC 3339 timestamp", value)
}

var tokenExpiryPattern = regexp.MustCompile(`^(\d+)d$`)

// ParseTokenExpiry parses token create --expires: Nd (1..365) or "never".
// It returns nil for never.
func ParseTokenExpiry(value string) (*int, error) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "never" {
		return nil, nil
	}

	match := tokenExpiryPattern.FindStringSubmatch(trimmed)
	if match != nil {
		days, err := strconv.Atoi(match[1])
		if err == nil && days >= 1 && days <= 365 {
			return &days, nil
		}
	}

	return nil, UsageError("invalid --expires %q: use a number of days between 1d and 365d, or never", value)
}
