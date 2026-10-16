package pastevault

import (
	"net/url"
	"regexp"
	"strings"
)

// Share references accepted by "get", "status" and "revoke":
//
//	https://host[/prefix]/p/<slug>[#k=KEY]   paste URL
//	https://host[/prefix]/f/<slug>[#k=KEY]   file share URL
//	<slug>#k=KEY                              short reference
//	<slug>                                    bare slug
//	pv://share/<slug>[?server=HOST][#k=KEY]   handle (docs/cli-reference.md)
//
// pv://secret/NAME handles name entries of the local store; they are not
// share references.
const (
	HandleScheme       = "pv"
	shareHandlePrefix  = "pv://share/"
	secretHandlePrefix = "pv://secret/"
)

var slugPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// IsValidSlug reports whether value can be a share slug.
func IsValidSlug(value string) bool {
	return slugPattern.MatchString(value)
}

// ParseShareReference resolves a share reference. defaultServer is used for
// slugs and handles without a server; a URL on defaultPublic (the web origin
// of defaultServer) is mapped back to defaultServer, since the API may live
// on another host.
func ParseShareReference(raw, defaultServer, defaultPublic string) (ShareReference, error) {
	input := strings.TrimSpace(raw)
	if input == "" {
		return ShareReference{}, UsageError("share URL or slug is required")
	}

	lower := strings.ToLower(input)
	switch {
	case strings.HasPrefix(lower, secretHandlePrefix):
		return ShareReference{}, UsageError("%s is a local secret handle, not a share; secret handles are used by pastevault run and inject", redactFragment(input))
	case strings.HasPrefix(lower, HandleScheme+"://"):
		return parseShareHandle(input, defaultServer)
	case strings.Contains(input, "://"):
		return parseShareURL(input, defaultServer, defaultPublic)
	}

	if strings.Contains(input, "/") {
		return ShareReference{}, UsageError("unrecognised share reference %q: expected a /p/ or /f/ URL, a slug or pv://share/<slug>", redactFragment(input))
	}

	slug, fragment, _ := strings.Cut(input, "#")
	if !IsValidSlug(slug) {
		return ShareReference{}, UsageError("invalid share slug %q", slug)
	}

	ref := ShareReference{Server: defaultServer, Slug: slug}
	key, err := keyFromFragment(fragment)
	if err != nil {
		return ShareReference{}, err
	}
	ref.Key = key

	return ref, nil
}

func parseShareURL(input, defaultServer, defaultPublic string) (ShareReference, error) {
	parsedURL, err := url.Parse(input)
	if err != nil || parsedURL.Host == "" {
		return ShareReference{}, UsageError("invalid share URL %q", redactFragment(input))
	}
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return ShareReference{}, UsageError("share URLs must use http or https")
	}

	segments := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
	if len(segments) < 2 {
		return ShareReference{}, UsageError("share URL must point to /p/<slug> or /f/<slug>")
	}

	kind := ShareKindUnknown
	switch segments[len(segments)-2] {
	case "p":
		kind = ShareKindPaste
	case "f":
		kind = ShareKindFileShare
	default:
		return ShareReference{}, UsageError("share URL must point to /p/<slug> or /f/<slug>")
	}

	slug := segments[len(segments)-1]
	if !IsValidSlug(slug) {
		return ShareReference{}, UsageError("invalid share slug %q", slug)
	}

	serverURL := url.URL{Scheme: parsedURL.Scheme, Host: parsedURL.Host}
	if prefix := segments[:len(segments)-2]; len(prefix) > 0 {
		serverURL.Path = "/" + strings.Join(prefix, "/")
	}

	ref := ShareReference{Server: serverURL.String(), Slug: slug, Kind: kind}
	if sameURLBase(ref.Server, defaultPublic) {
		ref.Server = defaultServer
	}

	key, err := keyFromFragment(parsedURL.Fragment)
	if err != nil {
		return ShareReference{}, err
	}
	ref.Key = key

	return ref, nil
}

func parseShareHandle(input, defaultServer string) (ShareReference, error) {
	if !strings.HasPrefix(strings.ToLower(input), shareHandlePrefix) {
		return ShareReference{}, UsageError("unsupported handle %q: expected pv://share/<slug>", redactFragment(input))
	}

	rest, fragment, _ := strings.Cut(input[len(shareHandlePrefix):], "#")
	slug, rawQuery, _ := strings.Cut(rest, "?")
	if !IsValidSlug(slug) {
		return ShareReference{}, UsageError("invalid share slug %q in handle", slug)
	}

	ref := ShareReference{Server: defaultServer, Slug: slug}
	if rawQuery != "" {
		values, err := url.ParseQuery(rawQuery)
		if err != nil {
			return ShareReference{}, UsageError("invalid handle parameters: %v", err)
		}
		for name, list := range values {
			if len(list) == 0 {
				continue
			}
			switch name {
			case "server":
				ref.Server = list[0]
			case "var", "agent":
				if ref.Params == nil {
					ref.Params = map[string]string{}
				}
				ref.Params[name] = list[0]
			default:
				return ShareReference{}, UsageError("unknown handle parameter %q (expected server, var or agent)", name)
			}
		}
	}

	key, err := keyFromFragment(fragment)
	if err != nil {
		return ShareReference{}, err
	}
	ref.Key = key

	return ref, nil
}

// keyFromFragment reads k=KEY from a URL fragment. Errors never echo the key.
func keyFromFragment(fragment string) ([]byte, error) {
	if fragment == "" {
		return nil, nil
	}

	values, err := url.ParseQuery(fragment)
	if err != nil {
		return nil, UsageError("the share URL fragment is malformed")
	}

	keyValue := values.Get("k")
	if keyValue == "" {
		return nil, nil
	}

	return DecodeShareKey(keyValue)
}

// DecodeShareKey decodes a base64url share key and checks its length. Errors
// never echo the key.
func DecodeShareKey(value string) ([]byte, error) {
	key, err := DecodeBase64URL(strings.TrimSpace(value))
	if err != nil {
		return nil, UsageError("the share key is not valid base64url")
	}
	if len(key) != 32 {
		return nil, UsageError("the share key must be 32 bytes (43 base64url characters), got %d bytes", len(key))
	}

	return key, nil
}

// redactFragment drops a URL fragment (which may carry a key) from text that
// goes into an error message.
func redactFragment(value string) string {
	if before, _, found := strings.Cut(value, "#"); found {
		return before + "#…"
	}

	return value
}

func sameURLBase(left, right string) bool {
	leftURL, err := url.Parse(strings.TrimSpace(left))
	if err != nil {
		return false
	}

	rightURL, err := url.Parse(strings.TrimSpace(right))
	if err != nil {
		return false
	}

	return strings.EqualFold(leftURL.Scheme, rightURL.Scheme) &&
		strings.EqualFold(leftURL.Host, rightURL.Host) &&
		strings.TrimRight(leftURL.Path, "/") == strings.TrimRight(rightURL.Path, "/")
}
