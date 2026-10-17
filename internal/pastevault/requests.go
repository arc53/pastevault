package pastevault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"
)

// Secret requests (spec §2.6, §3.3, §6). An agent asks its account's human
// for a secret: the CLI generates an ephemeral X25519 key per request, the
// human's browser seals the answer to it, and the CLI opens it, re-seals it
// into the local store and acknowledges delivery.

// RequestCodeAlphabet has no look-alike characters (no 0/O, 1/I).
const RequestCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

var (
	secretNamePattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
	requestCodePattern = regexp.MustCompile(`^[` + RequestCodeAlphabet + `]{8}$`)
	requestIDPattern   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// ValidSecretName reports whether name is a valid request or store name
// (the server's rule: letters, digits, "_", "." and "-", starting with a
// letter or "_", at most 128 characters).
func ValidSecretName(name string) bool {
	return secretNamePattern.MatchString(name)
}

// NormalizeRequestCode turns "abcd-efgh", "ABCD EFGH" or "ABCDEFGH" into
// "ABCD-EFGH". ok is false when value is not a request code.
func NormalizeRequestCode(value string) (string, bool) {
	code := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(value)))
	if !requestCodePattern.MatchString(code) {
		return "", false
	}

	return code[:4] + "-" + code[4:], true
}

// Request statuses.
const (
	RequestPending   = "pending"
	RequestFulfilled = "fulfilled"
	RequestDelivered = "delivered"
	RequestDeclined  = "declined"
	RequestExpired   = "expired"
	RequestCancelled = "cancelled"
)

// Payload kinds and accept values.
const (
	SecretKindText = "text"
	SecretKindFile = "file"
	AcceptAny      = "any"
)

type CreateSecretRequestRequest struct {
	Name        string `json:"name"`
	Reason      string `json:"reason,omitempty"`
	TTLSeconds  int    `json:"ttl_seconds"`
	Accept      string `json:"accept"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	AgentID     string `json:"agent_id"`
}

type CreateSecretRequestResponse struct {
	ID        string `json:"id"`
	Code      string `json:"code"`
	URLPath   string `json:"url_path"`
	ExpiresAt string `json:"expires_at"`
	PollToken string `json:"poll_token"`
	Interval  int    `json:"interval"`
}

type SecretRequestAgent struct {
	ID          string  `json:"id"`
	Name        *string `json:"name"`
	Fingerprint *string `json:"fingerprint,omitempty"`
}

// SecretRequestDetails is GET /api/secret-requests/by-code/:code (sessions
// of the requesting account only).
type SecretRequestDetails struct {
	ID          string  `json:"id"`
	Code        string  `json:"code"`
	Name        string  `json:"name"`
	Reason      *string `json:"reason"`
	Accept      string  `json:"accept"`
	PublicKey   string  `json:"public_key"`
	Fingerprint string  `json:"fingerprint"`
	MaxBytes    int     `json:"max_bytes"`
	Requester   struct {
		Agent     SecretRequestAgent `json:"agent"`
		TokenName *string            `json:"token_name"`
	} `json:"requester"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

// SealedSecret is a sealed request response or store entry body.
type SealedSecret struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	WrappedKey string `json:"wrapped_key"`
}

type FulfillSecretRequestRequest struct {
	Kind string `json:"kind"`
	SealedSecret
}

type SecretRequestStatusResponse struct {
	Status string `json:"status"`
}

// PollSecretRequestResponse carries the sealed response when Status is
// "fulfilled".
type PollSecretRequestResponse struct {
	Status   string `json:"status"`
	Interval int    `json:"interval"`
	Kind     string `json:"kind,omitempty"`
	SealedSecret
}

type pollSecretRequestBody struct {
	PollToken string `json:"poll_token"`
}

// SecretRequestSummary is one row of GET /api/account/secret-requests
// (metadata only).
type SecretRequestSummary struct {
	ID          string  `json:"id"`
	Code        string  `json:"code"`
	Name        string  `json:"name"`
	Reason      *string `json:"reason"`
	Accept      string  `json:"accept"`
	Fingerprint string  `json:"fingerprint"`
	Status      string  `json:"status"`
	Requester   struct {
		Agent SecretRequestAgent `json:"agent"`
	} `json:"requester"`
	ResponseKind *string `json:"response_kind"`
	ResponseSize *int    `json:"response_size"`
	CreatedAt    string  `json:"created_at"`
	ExpiresAt    string  `json:"expires_at"`
	OpenedAt     *string `json:"opened_at"`
	FulfilledAt  *string `json:"fulfilled_at"`
	DeliveredAt  *string `json:"delivered_at"`
	AckedAt      *string `json:"acked_at"`
	ClosedAt     *string `json:"closed_at"`
}

type ListSecretRequestsResponse struct {
	Requests []SecretRequestSummary `json:"requests"`
}

func requestPath(id string, rest ...string) string {
	return path.Join(append([]string{"secret-requests", url.PathEscape(id)}, rest...)...)
}

func (c *Client) CreateSecretRequest(ctx context.Context, payload CreateSecretRequestRequest) (CreateSecretRequestResponse, error) {
	var response CreateSecretRequestResponse
	err := c.doJSON(ctx, http.MethodPost, "secret-requests", payload, "application/json", &response)
	return response, err
}

// GetSecretRequestByCode needs a login session of the requesting account.
func (c *Client) GetSecretRequestByCode(ctx context.Context, code string) (SecretRequestDetails, error) {
	var response SecretRequestDetails
	err := c.doJSON(ctx, http.MethodGet, path.Join("secret-requests", "by-code", url.PathEscape(code)), nil, "", &response)
	return response, err
}

// FulfillSecretRequest needs a login session of the requesting account.
func (c *Client) FulfillSecretRequest(ctx context.Context, id string, payload FulfillSecretRequestRequest) error {
	return c.doJSON(ctx, http.MethodPost, requestPath(id, "fulfill"), payload, "application/json", &SecretRequestStatusResponse{})
}

func (c *Client) DeclineSecretRequest(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, requestPath(id, "decline"), nil, "", &SecretRequestStatusResponse{})
}

// PollSecretRequest asks for the response. Polling faster than the interval
// gives 429 {"error":"slow_down"} (see IsSlowDown).
func (c *Client) PollSecretRequest(ctx context.Context, id, pollToken string) (PollSecretRequestResponse, error) {
	var response PollSecretRequestResponse
	err := c.doJSON(ctx, http.MethodPost, requestPath(id, "poll"), pollSecretRequestBody{PollToken: pollToken}, "application/json", &response)
	return response, err
}

// AckSecretRequest tells the server the response is stored; it is wiped.
func (c *Client) AckSecretRequest(ctx context.Context, id, pollToken string) error {
	return c.doJSON(ctx, http.MethodPost, requestPath(id, "ack"), pollSecretRequestBody{PollToken: pollToken}, "application/json", nil)
}

func (c *Client) CancelSecretRequest(ctx context.Context, id string) (SecretRequestStatusResponse, error) {
	var response SecretRequestStatusResponse
	err := c.doJSON(ctx, http.MethodDelete, requestPath(id), nil, "", &response)
	return response, err
}

func (c *Client) ListSecretRequests(ctx context.Context, status string) (ListSecretRequestsResponse, error) {
	values := url.Values{}
	setQuery(values, "status", status)

	var response ListSecretRequestsResponse
	err := c.doJSON(ctx, http.MethodGet, withQuery("account/secret-requests", values), nil, "", &response)
	return response, err
}

// IsSlowDown reports a 429 slow_down answer to a poll.
func IsSlowDown(err error) bool {
	var apiErr *APIRequestError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusTooManyRequests && apiErr.ErrorCode == "slow_down"
}

// ── payload (spec §3.3, §3.4) ─────────────────────────────────────────────

const secretPayloadVersion = 1

// SecretPayload is the plaintext of a request response or a store entry:
//
//	{"v":1,"name":"OPENAI_API_KEY","kind":"text","value":"…"}
//	{"v":1,"name":"…","kind":"file","filename":"…","content_type":"…","data":"<b64url>"}
type SecretPayload struct {
	V           int    `json:"v"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Value       string `json:"value,omitempty"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Data        string `json:"data,omitempty"`
}

// NewTextPayload builds a text payload. JSON strings are UTF-8, so other
// bytes must be sent as a file.
func NewTextPayload(name string, value []byte) (SecretPayload, error) {
	if !utf8.Valid(value) {
		return SecretPayload{}, UsageError("the value is not valid UTF-8 text; send it as a file instead")
	}

	return SecretPayload{V: secretPayloadVersion, Name: name, Kind: SecretKindText, Value: string(value)}, nil
}

// NewFilePayload builds a file payload.
func NewFilePayload(name, filename, contentType string, data []byte) SecretPayload {
	return SecretPayload{
		V:           secretPayloadVersion,
		Name:        name,
		Kind:        SecretKindFile,
		Filename:    filename,
		ContentType: contentType,
		Data:        EncodeBase64URL(data),
	}
}

// Bytes returns the secret: the text value, or the decoded file data.
func (p SecretPayload) Bytes() ([]byte, error) {
	switch p.Kind {
	case SecretKindText:
		return []byte(p.Value), nil
	case SecretKindFile:
		data, err := DecodeBase64URL(p.Data)
		if err != nil {
			return nil, errors.New("the file data is not valid base64url")
		}
		return data, nil
	}

	return nil, fmt.Errorf("unknown secret kind %q", p.Kind)
}

func (p SecretPayload) validate() error {
	if p.V != secretPayloadVersion {
		return fmt.Errorf("unsupported secret payload version %d", p.V)
	}
	if p.Kind != SecretKindText && p.Kind != SecretKindFile {
		return fmt.Errorf("unknown secret kind %q", p.Kind)
	}
	_, err := p.Bytes()
	return err
}

// RequestPayloadAAD and StorePayloadAAD bind a payload's ciphertext to the
// request or store entry it belongs to.
func RequestPayloadAAD(id string) string { return "pastevault:request:" + id + ":v1" }
func StorePayloadAAD(name string) string { return "pastevault:store:" + name + ":v1" }

// SealSecretPayload encrypts payload with a fresh content key K under aad
// and wraps K to recipientPublicKey for wrapContext (PVWRAP1).
func SealSecretPayload(payload SecretPayload, recipientPublicKey []byte, wrapContext, aad string) (SealedSecret, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return SealedSecret{}, err
	}
	plaintext := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))

	key, err := randomBytes(ContentKeySize)
	if err != nil {
		return SealedSecret{}, err
	}
	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return SealedSecret{}, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return SealedSecret{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(aad))
	wrapped, err := WrapKey(key, recipientPublicKey, wrapContext)
	if err != nil {
		return SealedSecret{}, err
	}

	return SealedSecret{
		Ciphertext: EncodeBase64URL(ciphertext),
		Nonce:      EncodeBase64URL(nonce),
		WrappedKey: wrapped,
	}, nil
}

// OpenSecretPayload reverses SealSecretPayload. Every failure (wrong key,
// wrong context or AAD, tampering) is a decryption error (exit 7).
func OpenSecretPayload(sealed SealedSecret, recipientPrivateKey []byte, wrapContext, aad string) (SecretPayload, error) {
	key, err := UnwrapKey(sealed.WrappedKey, recipientPrivateKey, wrapContext)
	if err != nil {
		return SecretPayload{}, DecryptError("could not unwrap the secret's key: it was sealed to another key or tampered with")
	}

	ciphertext, err := decodeStrictBase64URL(sealed.Ciphertext)
	if err != nil {
		return SecretPayload{}, DecryptError("the sealed secret is not valid base64url")
	}
	nonce, err := decodeStrictBase64URL(sealed.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return SecretPayload{}, DecryptError("the sealed secret has an invalid nonce")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return SecretPayload{}, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return SecretPayload{}, DecryptError("could not decrypt the secret: it was tampered with or belongs to something else")
	}

	var payload SecretPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return SecretPayload{}, DecryptError("the decrypted secret is not a valid payload")
	}
	if err := payload.validate(); err != nil {
		return SecretPayload{}, DecryptError("the decrypted secret is not a valid payload: %v", err)
	}

	return payload, nil
}

// SealedSize is the decoded ciphertext size, the number the server limits
// (max_secret_request_bytes).
func (s SealedSecret) SealedSize() int {
	return len(s.Ciphertext) * 3 / 4
}

// ── pending requests on disk (spec §4) ─────────────────────────────────────

// PendingRequest is <ConfigDir>/requests/<id>.json: what the CLI needs to
// collect a response. It holds the request's ephemeral private key and poll
// token, so it is 0600 and deleted after the ack.
type PendingRequest struct {
	V           int    `json:"v"`
	ID          string `json:"id"`
	Code        string `json:"code"`
	Server      string `json:"server"`
	URL         string `json:"url"`
	Name        string `json:"name"`
	SaveAs      string `json:"save_as"`
	Overwrite   bool   `json:"overwrite,omitempty"`
	Accept      string `json:"accept"`
	PollToken   string `json:"poll_token"`
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Interval    int    `json:"interval"`
	ExpiresAt   string `json:"expires_at"`
	CreatedAt   string `json:"created_at"`
	// The agent the request was made as; the response is stored for it.
	Agent            string `json:"agent"`
	AgentID          string `json:"agent_id"`
	AgentFingerprint string `json:"agent_fingerprint"`

	Path string `json:"-"`
}

const pendingRequestVersion = 1

func requestsDir() (string, error) {
	configDir, err := ConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, "requests"), nil
}

func pendingRequestPath(id string) (string, error) {
	if !requestIDPattern.MatchString(id) {
		return "", UsageError("invalid request id %q", id)
	}
	dir, err := requestsDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, id+".json"), nil
}

// SavePendingRequest writes the request file (0600, directory 0700).
func SavePendingRequest(request *PendingRequest) error {
	request.V = pendingRequestVersion
	target, err := pendingRequestPath(request.ID)
	if err != nil {
		return err
	}
	if err := writePrivateJSON(target, request); err != nil {
		return WrapError(ExitLocalFile, CodeLocalFile, err, "could not save the request file")
	}
	request.Path = target

	return nil
}

func readPendingRequest(target string) (*PendingRequest, error) {
	data, err := os.ReadFile(target)
	if err != nil {
		return nil, err
	}
	tightenPermissions(target, 0o600)

	var request PendingRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", target, err)
	}
	if request.V != pendingRequestVersion || request.ID == "" || request.PollToken == "" || request.PrivateKey == "" {
		return nil, fmt.Errorf("%s is not a valid request file", target)
	}
	request.Path = target

	return &request, nil
}

// Keys returns the request's ephemeral key pair, checked against the stored
// public key and fingerprint.
func (r *PendingRequest) Keys() (AgentKeyPair, error) {
	keys, err := DecodeAgentPrivateKey(r.PrivateKey)
	if err != nil {
		return AgentKeyPair{}, err
	}
	if EncodeBase64URL(keys.PublicKey) != r.PublicKey || keys.Fingerprint != r.Fingerprint {
		return AgentKeyPair{}, fmt.Errorf("the request file %s is damaged (key mismatch)", r.Path)
	}

	return keys, nil
}

// ListPendingRequests lists the request files, oldest first. Damaged files
// are skipped and reported as warnings.
func ListPendingRequests() ([]*PendingRequest, []string, error) {
	dir, err := requestsDir()
	if err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	var requests []*PendingRequest
	var warnings []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		request, err := readPendingRequest(filepath.Join(dir, entry.Name()))
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		requests = append(requests, request)
	}
	sort.SliceStable(requests, func(i, j int) bool { return requests[i].CreatedAt < requests[j].CreatedAt })

	return requests, warnings, nil
}

// FindPendingRequest finds a request file by request id or code. It returns
// nil when this machine has none.
func FindPendingRequest(idOrCode string) (*PendingRequest, error) {
	if code, ok := NormalizeRequestCode(idOrCode); ok {
		requests, _, err := ListPendingRequests()
		if err != nil {
			return nil, err
		}
		for _, request := range requests {
			if request.Code == code {
				return request, nil
			}
		}
		return nil, nil
	}

	target, err := pendingRequestPath(idOrCode)
	if err != nil {
		return nil, err
	}
	request, err := readPendingRequest(target)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	return request, err
}

// DeletePendingRequest removes the request file (and with it the ephemeral
// private key and poll token).
func DeletePendingRequest(request *PendingRequest) error {
	target := request.Path
	if target == "" {
		var err error
		if target, err = pendingRequestPath(request.ID); err != nil {
			return err
		}
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return nil
}

// Expired reports whether the request's expiry has passed.
func (r *PendingRequest) Expired(now time.Time) bool {
	expires, err := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	return err == nil && !now.Before(expires)
}

// RequestURL is the page a human opens to answer: the web origin, /r/CODE,
// and #fp= so the page can check the request key (spec §6).
func RequestURL(publicBase, code, fingerprint string) string {
	return strings.TrimRight(publicBase, "/") + "/r/" + code + "#fp=" + fingerprint
}

// ParseRequestReference accepts a request code ("ABCD-EFGH"), or a request
// URL (".../r/ABCD-EFGH#fp=pvk1_…"). It returns the normalized code and the
// fingerprint from the URL ("" when there is none).
func ParseRequestReference(value string) (code string, fingerprint string, err error) {
	input := strings.TrimSpace(value)
	if strings.Contains(input, "://") || strings.Contains(input, "/r/") {
		parsed, parseErr := url.Parse(input)
		if parseErr != nil {
			return "", "", UsageError("invalid request URL")
		}
		segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(segments) < 2 || segments[len(segments)-2] != "r" {
			return "", "", UsageError("a request URL must point to /r/<code>")
		}
		input = segments[len(segments)-1]
		if parsed.Fragment != "" {
			values, fragmentErr := url.ParseQuery(parsed.Fragment)
			if fragmentErr != nil {
				return "", "", UsageError("the request URL fragment is malformed")
			}
			fingerprint = values.Get("fp")
			if fingerprint != "" && !IsFingerprint(fingerprint) {
				return "", "", UsageError("the request URL's #fp= is not a full key fingerprint")
			}
		}
	}

	code, ok := NormalizeRequestCode(input)
	if !ok {
		return "", "", UsageError("%q is not a request code (like ABCD-EFGH) or request URL", input)
	}

	return code, fingerprint, nil
}
