package pastevault

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Exit codes are part of the CLI contract (docs/cli-reference.md). Scripts and
// agents branch on them, so never renumber an existing code.
const (
	ExitOK          = 0
	ExitInternal    = 1
	ExitUsage       = 2
	ExitAuth        = 3
	ExitNotFound    = 4
	ExitGone        = 5
	ExitDeclined    = 6
	ExitDecrypt     = 7
	ExitFingerprint = 8
	ExitTimeout     = 9
	ExitRateLimited = 10
	ExitNetwork     = 11
	ExitConflict    = 12
	ExitLocalFile   = 13
	ExitUnsupported = 14
	ExitInterrupted = 130
)

// Machine-readable error codes, paired with the exit codes above.
const (
	CodeInternal       = "internal"
	CodeUsage          = "usage"
	CodeInvalidRequest = "invalid_request"
	CodeTooLarge       = "too_large"
	CodeAuth           = "auth"
	CodeNotFound       = "not_found"
	CodeGone           = "gone"
	CodeDeclined       = "declined"
	CodeDecrypt        = "decrypt_failed"
	CodeFingerprint    = "fingerprint_mismatch"
	CodeTimeout        = "timeout"
	CodeRateLimited    = "rate_limited"
	CodeNetwork        = "network"
	CodeConflict       = "conflict"
	CodeLocalFile      = "local_file"
	CodeUnsupported    = "unsupported"
	CodeInterrupted    = "interrupted"
	CodeKeyRequired    = "key_required"
	CodePasswordNeeded = "password_required"
	CodeSealedShare    = "sealed_share"
	// CodeSealedConflict: the server says a share is sealed, but the link
	// has a key (or the share a password); possible tampering.
	CodeSealedConflict  = "sealed_share_conflict"
	CodeNotLoggedIn     = "not_logged_in"
	CodeSessionRequired = "session_required"
)

// CLIError is an error with a stable exit code and machine-readable code.
// Messages must never contain keys, passwords or tokens.
type CLIError struct {
	Exit    int
	Code    string
	Message string
	Err     error
}

func (e *CLIError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}

	return e.Code
}

func (e *CLIError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

// NewError builds a CLIError with a formatted message.
func NewError(exit int, code, format string, args ...any) *CLIError {
	return &CLIError{Exit: exit, Code: code, Message: fmt.Sprintf(format, args...)}
}

// WrapError attaches an exit code to err while keeping it inspectable with
// errors.Is/As.
func WrapError(exit int, code string, err error, format string, args ...any) *CLIError {
	message := fmt.Sprintf(format, args...)
	if err != nil {
		message = message + ": " + err.Error()
	}

	return &CLIError{Exit: exit, Code: code, Message: message, Err: err}
}

// UsageError reports a flag or argument problem (exit 2).
func UsageError(format string, args ...any) *CLIError {
	return NewError(ExitUsage, CodeUsage, format, args...)
}

// DecryptError reports a wrong key or password, or tampered content (exit 7).
func DecryptError(format string, args ...any) *CLIError {
	return NewError(ExitDecrypt, CodeDecrypt, format, args...)
}

// UnsupportedError reports that the server lacks a feature (exit 14).
func UnsupportedError(format string, args ...any) *CLIError {
	return NewError(ExitUnsupported, CodeUnsupported, format, args...)
}

// Classify maps any error to a CLIError. Errors that already carry an exit
// code keep it; API errors are mapped by HTTP status; transport failures are
// network errors; cancellation is an interrupt.
func Classify(err error) *CLIError {
	if err == nil {
		return nil
	}

	var cliErr *CLIError
	if errors.As(err, &cliErr) {
		return cliErr
	}

	var apiErr *APIRequestError
	if errors.As(err, &apiErr) {
		// The server's stored fingerprint for an agent differs from the one
		// this CLI computed from the key it was given.
		if apiErr.Code == "recipient_fingerprint_mismatch" || apiErr.Code == "fingerprint_mismatch" {
			return &CLIError{Exit: ExitFingerprint, Code: CodeFingerprint, Message: describeAPIError(apiErr), Err: err}
		}
		exit, code := ExitCodeForStatus(apiErr.StatusCode)
		return &CLIError{Exit: exit, Code: code, Message: describeAPIError(apiErr), Err: err}
	}

	if errors.Is(err, context.Canceled) {
		return &CLIError{Exit: ExitInterrupted, Code: CodeInterrupted, Message: "interrupted", Err: err}
	}

	var netErr net.Error
	var urlErr *url.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) || errors.As(err, &urlErr) {
		return &CLIError{Exit: ExitNetwork, Code: CodeNetwork, Message: err.Error(), Err: err}
	}

	return &CLIError{Exit: ExitInternal, Code: CodeInternal, Message: err.Error(), Err: err}
}

// ExitCodeForStatus maps an HTTP error status to the CLI exit code table.
func ExitCodeForStatus(status int) (int, string) {
	switch {
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
		return ExitUsage, CodeInvalidRequest
	case status == http.StatusRequestEntityTooLarge:
		return ExitUsage, CodeTooLarge
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return ExitAuth, CodeAuth
	case status == http.StatusNotFound:
		return ExitNotFound, CodeNotFound
	case status == http.StatusGone:
		return ExitGone, CodeGone
	case status == http.StatusConflict:
		return ExitConflict, CodeConflict
	case status == http.StatusTooManyRequests:
		return ExitRateLimited, CodeRateLimited
	case status >= 300 && status < 400:
		return ExitNetwork, CodeNetwork
	case status == http.StatusNotImplemented:
		return ExitUnsupported, CodeUnsupported
	case status >= 500:
		return ExitNetwork, CodeNetwork
	default:
		return ExitInternal, CodeInternal
	}
}

// describeAPIError turns a server answer into a short message with a hint for
// the cases a user can act on.
func describeAPIError(apiErr *APIRequestError) string {
	message := apiErr.Error()

	switch {
	case apiErr.ErrorCode == "invalid_token":
		return message + " (the API token is unknown, revoked or expired; check PASTEVAULT_TOKEN or run pastevault login --with-token)"
	case apiErr.ErrorCode == "insufficient_scope" && apiErr.Required != "":
		return message + fmt.Sprintf(" (the API token lacks the %s scope)", apiErr.Required)
	case apiErr.ErrorCode == "recipient_auth_required":
		return message + " (a share sealed to an agent can only be opened with credentials of the recipient's account: pastevault login, or an API token with shares:receive)"
	case apiErr.ErrorCode == "session_required":
		return message + " (this needs a browser-approved login: run pastevault login)"
	case apiErr.StatusCode == http.StatusUnauthorized && strings.EqualFold(apiErr.ErrorCode, "Authentication required"):
		return message + " (run pastevault login or set PASTEVAULT_TOKEN)"
	}

	return message
}

// IsStatus reports whether err is an API error with the given HTTP status.
func IsStatus(err error, status int) bool {
	var apiErr *APIRequestError
	return errors.As(err, &apiErr) && apiErr.StatusCode == status
}
