package pastevault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	UploadTokenHeader   = "X-Upload-Token"
	DownloadGrantHeader = "X-Download-Grant"
)

type Client struct {
	baseURL     *url.URL
	apiBaseURL  *url.URL
	authBaseURL *url.URL
	httpClient  *http.Client
	userAgent   string
	authToken   string
	// Backoff between chunk download attempts; one retry per entry.
	chunkRetryDelays []time.Duration
}

func NewClient(server, version string) (*Client, error) {
	baseURL, apiURL, err := normalizeServerURL(server)
	if err != nil {
		return nil, err
	}

	return &Client{
		baseURL:     baseURL,
		apiBaseURL:  apiURL,
		authBaseURL: resolveAuthBaseURL(apiURL),
		httpClient:  &http.Client{Timeout: 90 * time.Second},
		userAgent:   fmt.Sprintf("pastevault/%s", version),
		chunkRetryDelays: []time.Duration{
			time.Second,
			2 * time.Second,
			4 * time.Second,
			8 * time.Second,
		},
	}, nil
}

func (c *Client) BaseURL() string {
	return strings.TrimRight(c.baseURL.String(), "/")
}

func (c *Client) SetAuthToken(token string) {
	c.authToken = strings.TrimSpace(token)
}

// HasAuthToken reports whether requests carry a bearer credential.
func (c *Client) HasAuthToken() bool {
	return c.authToken != ""
}

func (c *Client) GetCapabilities(ctx context.Context) (CapabilitiesResponse, error) {
	var response CapabilitiesResponse
	err := c.doJSON(ctx, http.MethodGet, "capabilities", nil, "", &response)
	return response, err
}

func (c *Client) CreatePaste(ctx context.Context, payload CreatePasteRequest) (CreatePasteResponse, error) {
	var response CreatePasteResponse
	err := c.doJSON(ctx, http.MethodPost, "pastes", payload, "application/json", &response)
	return response, err
}

// GetPasteMeta describes a paste without consuming a view.
func (c *Client) GetPasteMeta(ctx context.Context, slug string) (PasteMetaResponse, error) {
	var response PasteMetaResponse
	err := c.doJSON(ctx, http.MethodGet, path.Join("pastes", url.PathEscape(slug), "meta"), nil, "", &response)
	return response, err
}

// GetPaste opens a paste and consumes a view; the last allowed view burns it.
func (c *Client) GetPaste(ctx context.Context, slug string) (GetPasteResponse, error) {
	var response GetPasteResponse
	err := c.doJSON(ctx, http.MethodGet, path.Join("pastes", url.PathEscape(slug)), nil, "", &response)
	return response, err
}

func (c *Client) GetMe(ctx context.Context) (MeResponse, error) {
	var response MeResponse
	err := c.doJSON(ctx, http.MethodGet, "me", nil, "", &response)
	return response, err
}

func (c *Client) CreateAPIToken(ctx context.Context, payload CreateAPITokenRequest) (CreateAPITokenResponse, error) {
	var response CreateAPITokenResponse
	err := c.doJSON(ctx, http.MethodPost, "account/tokens", payload, "application/json", &response)
	return response, err
}

func (c *Client) ListAPITokens(ctx context.Context) (ListAPITokensResponse, error) {
	var response ListAPITokensResponse
	err := c.doJSON(ctx, http.MethodGet, "account/tokens", nil, "", &response)
	return response, err
}

func (c *Client) RevokeAPIToken(ctx context.Context, id string) (RevokeAPITokenResponse, error) {
	var response RevokeAPITokenResponse
	err := c.doJSON(ctx, http.MethodDelete, path.Join("account/tokens", url.PathEscape(id)), nil, "", &response)
	return response, err
}

func (c *Client) ListAccountShares(ctx context.Context, query AccountSharesQuery) (ListAccountSharesResponse, error) {
	values := url.Values{}
	setQuery(values, "share_type", query.ShareType)
	setQuery(values, "status", query.Status)
	setQuery(values, "slug", query.Slug)
	setQuery(values, "cursor", query.Cursor)
	if query.Limit > 0 {
		values.Set("limit", fmt.Sprintf("%d", query.Limit))
	}

	var response ListAccountSharesResponse
	err := c.doJSON(ctx, http.MethodGet, withQuery("account/shares", values), nil, "", &response)
	return response, err
}

func (c *Client) RevokeAccountShare(ctx context.Context, id string) (RevokeAccountShareResponse, error) {
	var response RevokeAccountShareResponse
	err := c.doJSON(ctx, http.MethodDelete, path.Join("account/shares", url.PathEscape(id)), nil, "", &response)
	return response, err
}

func (c *Client) ListShareEvents(ctx context.Context, id string) (ListShareEventsResponse, error) {
	var response ListShareEventsResponse
	err := c.doJSON(ctx, http.MethodGet, path.Join("account/shares", url.PathEscape(id), "events"), nil, "", &response)
	return response, err
}

func (c *Client) ListAuditEvents(ctx context.Context, query AuditQuery) (ListAuditEventsResponse, error) {
	values := url.Values{}
	setQuery(values, "since", query.Since)
	setQuery(values, "event", query.Event)
	setQuery(values, "cursor", query.Cursor)
	if query.Limit > 0 {
		values.Set("limit", fmt.Sprintf("%d", query.Limit))
	}

	var response ListAuditEventsResponse
	err := c.doJSON(ctx, http.MethodGet, withQuery("account/audit", values), nil, "", &response)
	return response, err
}

func setQuery(values url.Values, name, value string) {
	if value != "" {
		values.Set(name, value)
	}
}

func withQuery(relativePath string, values url.Values) string {
	if len(values) == 0 {
		return relativePath
	}

	return relativePath + "?" + values.Encode()
}

func (c *Client) CreateFileShare(ctx context.Context, payload CreateFileShareRequest) (CreateFileShareResponse, error) {
	var response CreateFileShareResponse
	err := c.doJSON(ctx, http.MethodPost, "file-shares", payload, "application/json", &response)
	return response, err
}

// optionalHeader returns a header set with name only when value is non-empty,
// so the CLI keeps working against older servers that issue no tokens.
func optionalHeader(name, value string) http.Header {
	if value == "" {
		return nil
	}

	return http.Header{name: []string{value}}
}

func (c *Client) UploadFileShareChunk(ctx context.Context, slug, uploadToken, fileID string, chunkIndex int, body []byte) error {
	relativePath := path.Join("file-shares", slug, "chunks", fileID, fmt.Sprintf("%d", chunkIndex))
	return c.doBytes(ctx, http.MethodPut, relativePath, bytes.NewReader(body), "application/octet-stream", optionalHeader(UploadTokenHeader, uploadToken), nil)
}

func (c *Client) CompleteFileShare(ctx context.Context, slug, uploadToken string, payload CompleteFileShareRequest) error {
	return c.doJSONAtBase(ctx, c.apiBaseURL, http.MethodPost, path.Join("file-shares", slug, "complete"), payload, "application/json", optionalHeader(UploadTokenHeader, uploadToken), nil)
}

// GetFileShareMeta describes a share without opening it, so it never burns a
// burn-after-read share.
func (c *Client) GetFileShareMeta(ctx context.Context, slug string) (FileShareMetaResponse, error) {
	var response FileShareMetaResponse
	err := c.doJSON(ctx, http.MethodGet, path.Join("file-shares", slug, "meta"), nil, "", &response)
	return response, err
}

// GetFileShare opens a share. Burn-after-read shares are destroyed by this call.
func (c *Client) GetFileShare(ctx context.Context, slug string) (GetFileShareResponse, error) {
	var response GetFileShareResponse
	err := c.doJSON(ctx, http.MethodGet, path.Join("file-shares", slug), nil, "", &response)
	return response, err
}

func (c *Client) DownloadFileShareChunk(ctx context.Context, slug, downloadGrant, fileID string, chunkIndex int) ([]byte, error) {
	var buffer bytes.Buffer
	relativePath := path.Join("file-shares", slug, "chunks", fileID, fmt.Sprintf("%d", chunkIndex))
	if err := c.doBytes(ctx, http.MethodGet, relativePath, nil, "", optionalHeader(DownloadGrantHeader, downloadGrant), &buffer); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// downloadChunkWithRetry retries transient failures (network errors, 429 and
// 5xx). Burned shares cannot be reopened, so a dropped connection must not end
// the download; 4xx answers such as an expired grant are final.
func (c *Client) downloadChunkWithRetry(ctx context.Context, slug, downloadGrant, fileID string, chunkIndex int) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		data, err := c.DownloadFileShareChunk(ctx, slug, downloadGrant, fileID, chunkIndex)
		if err == nil || attempt >= len(c.chunkRetryDelays) || !isRetryableError(err) || ctx.Err() != nil {
			return data, err
		}

		timer := time.NewTimer(c.chunkRetryDelays[attempt])
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func isRetryableError(err error) bool {
	var apiErr *APIRequestError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500
	}

	return true
}

func (c *Client) RequestDeviceCode(ctx context.Context, clientID string) (DeviceCodeResponse, error) {
	var response DeviceCodeResponse
	err := c.doAuthJSON(ctx, http.MethodPost, "device/code", DeviceCodeRequest{
		ClientID: clientID,
	}, "application/json", &response)
	return response, err
}

func (c *Client) ExchangeDeviceToken(ctx context.Context, deviceCode, clientID string) (DeviceTokenResponse, error) {
	var response DeviceTokenResponse
	err := c.doAuthJSON(ctx, http.MethodPost, "device/token", DeviceTokenRequest{
		GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
		DeviceCode: deviceCode,
		ClientID:   clientID,
	}, "application/json", &response)
	return response, err
}

func (c *Client) GetAuthSession(ctx context.Context) (*AuthSessionResponse, error) {
	var response *AuthSessionResponse
	if err := c.doAuthJSON(ctx, http.MethodGet, "get-session", nil, "", &response); err != nil {
		return nil, err
	}

	return response, nil
}

// SignOut revokes the session behind the current bearer token on the server.
func (c *Client) SignOut(ctx context.Context) error {
	return c.doAuthJSON(ctx, http.MethodPost, "sign-out", struct{}{}, "application/json", nil)
}

func (c *Client) doJSON(ctx context.Context, method, relativePath string, payload any, contentType string, target any) error {
	return c.doJSONAtBase(ctx, c.apiBaseURL, method, relativePath, payload, contentType, nil, target)
}

func (c *Client) doAuthJSON(ctx context.Context, method, relativePath string, payload any, contentType string, target any) error {
	return c.doJSONAtBase(ctx, c.authBaseURL, method, relativePath, payload, contentType, nil, target)
}

func (c *Client) doJSONAtBase(ctx context.Context, baseURL *url.URL, method, relativePath string, payload any, contentType string, headers http.Header, target any) error {
	var body io.Reader

	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}

	var (
		buffer         *bytes.Buffer
		responseTarget io.Writer
	)
	if target != nil {
		buffer = &bytes.Buffer{}
		responseTarget = buffer
	}

	if err := c.doBytesAtBase(ctx, baseURL, method, relativePath, body, contentType, headers, responseTarget); err != nil {
		return err
	}

	if target == nil {
		return nil
	}

	if err := json.Unmarshal(buffer.Bytes(), target); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	return nil
}

func (c *Client) doBytes(ctx context.Context, method, relativePath string, body io.Reader, contentType string, headers http.Header, target io.Writer) error {
	return c.doBytesAtBase(ctx, c.apiBaseURL, method, relativePath, body, contentType, headers, target)
}

func (c *Client) doBytesAtBase(ctx context.Context, baseURL *url.URL, method, relativePath string, body io.Reader, contentType string, headers http.Header, target io.Writer) error {
	requestURL := *baseURL
	relativePath, rawQuery, _ := strings.Cut(relativePath, "?")
	requestURL.Path = path.Join(baseURL.Path, relativePath)
	requestURL.RawQuery = rawQuery

	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return err
	}

	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", c.userAgent)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if c.authToken != "" {
		request.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		apiError := APIErrorResponse{}
		if len(data) > 0 && json.Unmarshal(data, &apiError) == nil && apiError.Error != "" {
			description := apiError.ErrorDescription
			if description == "" {
				description = apiError.Message
			}
			return &APIRequestError{
				Method:           method,
				Path:             requestURL.Path,
				StatusCode:       response.StatusCode,
				Status:           response.Status,
				ErrorCode:        apiError.Error,
				ErrorDescription: description,
				Code:             apiError.Code,
				Required:         apiError.Required,
			}
		}

		return &APIRequestError{
			Method:     method,
			Path:       requestURL.Path,
			StatusCode: response.StatusCode,
			Status:     response.Status,
		}
	}

	if target == nil {
		_, err = io.Copy(io.Discard, response.Body)
		return err
	}

	_, err = io.Copy(target, response.Body)
	return err
}

func resolveAuthBaseURL(apiBaseURL *url.URL) *url.URL {
	authURL := *apiBaseURL
	authURL.Path = path.Join(apiBaseURL.Path, "auth")
	return &authURL
}

func normalizeServerURL(raw string) (*url.URL, *url.URL, error) {
	server := strings.TrimSpace(raw)
	if server == "" {
		server = DefaultServerURL()
	}

	if !strings.Contains(server, "://") {
		if strings.HasPrefix(server, "localhost") || strings.HasPrefix(server, "127.0.0.1") {
			server = "http://" + server
		} else {
			server = "https://" + server
		}
	}

	baseURL, err := url.Parse(server)
	if err != nil {
		return nil, nil, err
	}

	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	if baseURL.Path == "/api" {
		baseOnly := *baseURL
		baseOnly.Path = ""
		return &baseOnly, baseURL, nil
	}

	apiURL := *baseURL
	apiURL.Path = path.Join("/", strings.TrimRight(baseURL.Path, "/"), "api")
	return baseURL, &apiURL, nil
}
