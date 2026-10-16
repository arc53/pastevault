package pastevault

import (
	"net/url"
	"strings"
)

// Handles name a secret without containing it (spec §5.4). They are used in
// .env.pv files, inject templates and MCP results:
//
//	pv://secret/NAME[?agent=AGENT&var=KEY&server=URL]   local store entry
//	pv://share/SLUG[?server=URL&var=KEY][#k=KEY]         share
//	https://host/p/SLUG#k=KEY, https://host/f/SLUG#k=KEY  share URL (legacy)
//
// var=KEY treats the content as a dotenv file and selects KEY from it.

// HandleKind says what a handle points at.
type HandleKind string

const (
	HandleSecret HandleKind = "secret"
	HandleShare  HandleKind = "share"
)

// Handle is a parsed handle. Errors and String never include a share key.
type Handle struct {
	Kind HandleKind
	// Secret handles: the store entry, and optionally the agent whose store
	// holds it and the server it belongs to ("" = defaults).
	Name   string
	Agent  string
	Server string
	// Share handles.
	Share ShareReference
	// Var selects one key of dotenv-formatted content.
	Var string
}

// SecretHandle is the handle of store entry name on the default agent.
func SecretHandle(name string) string {
	return secretHandlePrefix + name
}

// String is the handle without its share key.
func (h Handle) String() string {
	switch h.Kind {
	case HandleSecret:
		values := url.Values{}
		setQuery(values, "agent", h.Agent)
		setQuery(values, "server", h.Server)
		setQuery(values, "var", h.Var)
		return withQuery(secretHandlePrefix+h.Name, values)
	default:
		values := url.Values{}
		setQuery(values, "var", h.Var)
		return withQuery(shareHandlePrefix+h.Share.Slug, values)
	}
}

// LooksLikeHandle reports whether value is meant as a pv:// handle (and so
// must resolve, rather than pass through literally).
func LooksLikeHandle(value string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), HandleScheme+"://")
}

// ParseHandle parses a pv:// handle. With allowURLs, https share URLs are
// accepted too (inject templates, MCP). defaultServer and defaultPublic are
// as for ParseShareReference.
func ParseHandle(raw, defaultServer, defaultPublic string, allowURLs bool) (Handle, error) {
	input := strings.TrimSpace(raw)
	lower := strings.ToLower(input)

	switch {
	case strings.HasPrefix(lower, secretHandlePrefix):
		return parseSecretHandle(input)
	case strings.HasPrefix(lower, shareHandlePrefix):
		ref, err := parseShareHandle(input, defaultServer)
		if err != nil {
			return Handle{}, err
		}
		handle := Handle{Kind: HandleShare, Share: ref, Var: ref.Params["var"]}
		if agent := ref.Params["agent"]; agent != "" {
			return Handle{}, UsageError("pv://share handles take server= and var=, not agent=")
		}
		if handle.Var != "" && !validDotenvKey(handle.Var) {
			return Handle{}, UsageError("invalid var=%q in handle", handle.Var)
		}
		return handle, nil
	case strings.HasPrefix(lower, HandleScheme+"://"):
		return Handle{}, UsageError("unsupported handle %q: expected pv://secret/NAME or pv://share/SLUG", redactFragment(input))
	case allowURLs && (strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://")):
		ref, err := parseShareURL(input, defaultServer, defaultPublic)
		if err != nil {
			return Handle{}, err
		}
		return Handle{Kind: HandleShare, Share: ref}, nil
	}

	return Handle{}, UsageError("%q is not a handle (pv://secret/NAME or pv://share/SLUG)", redactFragment(input))
}

func parseSecretHandle(input string) (Handle, error) {
	rest := input[len(secretHandlePrefix):]
	if strings.Contains(rest, "#") {
		return Handle{}, UsageError("pv://secret handles have no #fragment")
	}
	name, rawQuery, _ := strings.Cut(rest, "?")
	if !ValidSecretName(name) {
		return Handle{}, UsageError("invalid secret name %q in handle (letters, digits, _ . -, starting with a letter or _)", name)
	}

	handle := Handle{Kind: HandleSecret, Name: name}
	if rawQuery == "" {
		return handle, nil
	}

	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return Handle{}, UsageError("invalid handle parameters: %v", err)
	}
	for key, list := range values {
		if len(list) != 1 {
			return Handle{}, UsageError("handle parameter %q must be given once", key)
		}
		switch key {
		case "agent":
			if !ValidAgentName(list[0]) {
				return Handle{}, UsageError("invalid agent=%q in handle", list[0])
			}
			handle.Agent = list[0]
		case "server":
			handle.Server = list[0]
		case "var":
			if !validDotenvKey(list[0]) {
				return Handle{}, UsageError("invalid var=%q in handle", list[0])
			}
			handle.Var = list[0]
		default:
			return Handle{}, UsageError("unknown handle parameter %q (expected agent, server or var)", key)
		}
	}

	return handle, nil
}
