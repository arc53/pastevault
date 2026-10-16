package pastevault

type PasswordKDFParams struct {
	Iterations int    `json:"iterations"`
	Algorithm  string `json:"algorithm"`
	Hash       string `json:"hash"`
	KeyLen     int    `json:"keyLen"`
}

type FileShareCapabilitiesResponse struct {
	FileShares FileShareCapabilities `json:"file_shares"`
}

type FileShareCapabilities struct {
	Enabled           bool `json:"enabled"`
	MaxShareSizeBytes int  `json:"max_share_size_bytes"`
	MaxFiles          int  `json:"max_files"`
	ChunkSizeBytes    int  `json:"chunk_size_bytes"`
	BurnAfterRead     bool `json:"burn_after_read"`
}

type CreateFileShareRequest struct {
	Slug           string `json:"slug,omitempty"`
	Salt           string `json:"salt,omitempty"`
	KDFParams      string `json:"kdf_params,omitempty"`
	ExpiresInHours int    `json:"expires_in_hours,omitempty"`
	FileCount      int    `json:"file_count"`
	TotalSizeBytes int64  `json:"total_size_bytes"`
	BurnAfterRead  bool   `json:"burn_after_read,omitempty"`
}

type CreateFileShareResponse struct {
	Slug          string `json:"slug"`
	ExpiresAt     string `json:"expires_at"`
	BurnAfterRead bool   `json:"burn_after_read"`
	// UploadToken authorizes chunk uploads and completion. Older servers omit it.
	UploadToken string `json:"upload_token"`
}

type CompleteFileShareRequest struct {
	ManifestCiphertext string `json:"manifest_ciphertext"`
	ManifestNonce      string `json:"manifest_nonce"`
}

type GetFileShareResponse struct {
	Metadata           FileShareMetadata `json:"metadata"`
	ManifestCiphertext string            `json:"manifest_ciphertext"`
	ManifestNonce      string            `json:"manifest_nonce"`
	Salt               string            `json:"salt"`
	KDFParams          string            `json:"kdf_params"`
	// DownloadGrant is issued when a burn-after-read share is opened and is
	// required to download its chunks for a short time afterwards.
	DownloadGrant          string `json:"download_grant"`
	DownloadGrantExpiresAt string `json:"download_grant_expires_at"`
}

type FileShareMetadata struct {
	ID             string `json:"id"`
	Slug           string `json:"slug"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
	ViewCount      int    `json:"view_count"`
	FileCount      int    `json:"file_count"`
	TotalSizeBytes string `json:"total_size_bytes"`
	BurnAfterRead  bool   `json:"burn_after_read"`
	IsBurned       bool   `json:"is_burned"`
}

// FileShareMetaResponse describes a share without opening (or burning) it.
type FileShareMetaResponse struct {
	Slug              string `json:"slug"`
	CreatedAt         string `json:"created_at"`
	ExpiresAt         string `json:"expires_at"`
	BurnAfterRead     bool   `json:"burn_after_read"`
	IsBurned          bool   `json:"is_burned"`
	PasswordProtected bool   `json:"password_protected"`
	Salt              string `json:"salt"`
	KDFParams         string `json:"kdf_params"`
	FileCount         int    `json:"file_count"`
	TotalSizeBytes    string `json:"total_size_bytes"`
}

type FileShareManifest struct {
	Version string                  `json:"version"`
	Paste   *FileShareManifestPaste `json:"paste,omitempty"`
	Files   []FileShareManifestFile `json:"files"`
}

type FileShareManifestPaste struct {
	Title        string `json:"title"`
	Body         string `json:"body"`
	RenderMode   string `json:"render_mode"`
	LanguageHint string `json:"language_hint,omitempty"`
}

type FileShareManifestFile struct {
	ID           string               `json:"id"`
	Name         string               `json:"name"`
	Size         int64                `json:"size"`
	Type         string               `json:"type"`
	LastModified int64                `json:"last_modified"`
	Chunks       []FileShareChunkInfo `json:"chunks"`
}

type FileShareChunkInfo struct {
	Index         int    `json:"index"`
	Nonce         string `json:"nonce"`
	PlaintextSize int    `json:"plaintext_size"`
}

type APIErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type APIRequestError struct {
	Method           string
	Path             string
	StatusCode       int
	Status           string
	ErrorCode        string
	ErrorDescription string
}

func (e *APIRequestError) Error() string {
	if e == nil {
		return ""
	}

	message := e.ErrorDescription
	if message == "" {
		message = e.ErrorCode
	}
	if message == "" {
		message = e.Status
	}

	return e.Method + " " + e.Path + " failed: " + message
}

type FileShareEncryption struct {
	Key       []byte
	Salt      string
	KDFParams string
}

func (f FileShareEncryption) ShareKey() []byte {
	if f.Salt != "" {
		return nil
	}

	return f.Key
}

type ShareReference struct {
	Server string
	Slug   string
	Key    []byte
}

type DeviceCodeRequest struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type DeviceTokenRequest struct {
	GrantType  string `json:"grant_type"`
	DeviceCode string `json:"device_code"`
	ClientID   string `json:"client_id"`
}

type DeviceTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type AuthSessionResponse struct {
	Session AuthSession `json:"session"`
	User    AuthUser    `json:"user"`
}

type AuthSession struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expiresAt"`
	Token     string `json:"token"`
	UserID    string `json:"userId"`
}

type AuthUser struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

type UploadInput struct {
	Path         string
	DisplayName  string
	ContentType  string
	Size         int64
	LastModified int64
}
