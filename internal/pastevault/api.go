package pastevault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type Client struct {
	baseURL     *url.URL
	apiBaseURL  *url.URL
	authBaseURL *url.URL
	httpClient  *http.Client
	userAgent   string
	authToken   string
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
	}, nil
}

func (c *Client) BaseURL() string {
	return strings.TrimRight(c.baseURL.String(), "/")
}

func (c *Client) SetAuthToken(token string) {
	c.authToken = strings.TrimSpace(token)
}

func (c *Client) GetCapabilities(ctx context.Context) (FileShareCapabilitiesResponse, error) {
	var response FileShareCapabilitiesResponse
	err := c.doJSON(ctx, http.MethodGet, "capabilities", nil, "", &response)
	return response, err
}

func (c *Client) CreateFileShare(ctx context.Context, payload CreateFileShareRequest) (CreateFileShareResponse, error) {
	var response CreateFileShareResponse
	err := c.doJSON(ctx, http.MethodPost, "file-shares", payload, "application/json", &response)
	return response, err
}

func (c *Client) UploadFileShareChunk(ctx context.Context, slug, fileID string, chunkIndex int, body []byte) error {
	relativePath := path.Join("file-shares", slug, "chunks", fileID, fmt.Sprintf("%d", chunkIndex))
	return c.doBytes(ctx, http.MethodPut, relativePath, bytes.NewReader(body), "application/octet-stream", nil)
}

func (c *Client) CompleteFileShare(ctx context.Context, slug string, payload CompleteFileShareRequest) error {
	return c.doJSON(ctx, http.MethodPost, path.Join("file-shares", slug, "complete"), payload, "application/json", nil)
}

func (c *Client) GetFileShare(ctx context.Context, slug string) (GetFileShareResponse, error) {
	var response GetFileShareResponse
	err := c.doJSON(ctx, http.MethodGet, path.Join("file-shares", slug), nil, "", &response)
	return response, err
}

func (c *Client) DownloadFileShareChunk(ctx context.Context, slug, fileID string, chunkIndex int) ([]byte, error) {
	var buffer bytes.Buffer
	relativePath := path.Join("file-shares", slug, "chunks", fileID, fmt.Sprintf("%d", chunkIndex))
	if err := c.doBytes(ctx, http.MethodGet, relativePath, nil, "", &buffer); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
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

func (c *Client) doJSON(ctx context.Context, method, relativePath string, payload any, contentType string, target any) error {
	return c.doJSONAtBase(ctx, c.apiBaseURL, method, relativePath, payload, contentType, target)
}

func (c *Client) doAuthJSON(ctx context.Context, method, relativePath string, payload any, contentType string, target any) error {
	return c.doJSONAtBase(ctx, c.authBaseURL, method, relativePath, payload, contentType, target)
}

func (c *Client) doJSONAtBase(ctx context.Context, baseURL *url.URL, method, relativePath string, payload any, contentType string, target any) error {
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

	if err := c.doBytesAtBase(ctx, baseURL, method, relativePath, body, contentType, responseTarget); err != nil {
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

func (c *Client) doBytes(ctx context.Context, method, relativePath string, body io.Reader, contentType string, target io.Writer) error {
	return c.doBytesAtBase(ctx, c.apiBaseURL, method, relativePath, body, contentType, target)
}

func (c *Client) doBytesAtBase(ctx context.Context, baseURL *url.URL, method, relativePath string, body io.Reader, contentType string, target io.Writer) error {
	requestURL := *baseURL
	requestURL.Path = path.Join(baseURL.Path, relativePath)

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

	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		apiError := APIErrorResponse{}
		if len(data) > 0 && json.Unmarshal(data, &apiError) == nil && apiError.Error != "" {
			return &APIRequestError{
				Method:           method,
				Path:             requestURL.Path,
				StatusCode:       response.StatusCode,
				Status:           response.Status,
				ErrorCode:        apiError.Error,
				ErrorDescription: apiError.ErrorDescription,
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
