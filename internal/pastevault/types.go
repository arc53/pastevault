package pastevault

type PasswordKDFParams struct {
	Iterations int    `json:"iterations"`
	Algorithm  string `json:"algorithm"`
	Hash       string `json:"hash"`
	KeyLen     int    `json:"keyLen"`
}

// CapabilitiesResponse is GET /api/capabilities. Fields beyond file_shares
// arrived with api_version 2; older servers leave them zero.
type CapabilitiesResponse struct {
	APIVersion int                   `json:"api_version"`
	Auth       AuthCapabilities      `json:"auth"`
	FileShares FileShareCapabilities `json:"file_shares"`
	Features   FeatureFlags          `json:"features"`
	Limits     CapabilityLimits      `json:"limits"`
}

type AuthCapabilities struct {
	Enabled       bool `json:"enabled"`
	SignupEnabled bool `json:"signup_enabled"`
}

type FeatureFlags struct {
	ExpiresInMinutes bool `json:"expires_in_minutes"`
	MaxViews         bool `json:"max_views"`
	APITokens        bool `json:"api_tokens"`
	Agents           bool `json:"agents"`
	SealedShares     bool `json:"sealed_shares"`
	SecretRequests   bool `json:"secret_requests"`
	Audit            bool `json:"audit"`
}

type CapabilityLimits struct {
	MaxViews                   int `json:"max_views"`
	MaxSecretRequestBytes      int `json:"max_secret_request_bytes"`
	MinSecretRequestTTLSeconds int `json:"min_secret_request_ttl_seconds"`
	// Not reported by current servers; DefaultMaxPasteBytes applies then.
	MaxPasteSizeBytes int `json:"max_paste_size_bytes"`
}

type FileShareCapabilities struct {
	Enabled           bool `json:"enabled"`
	MaxShareSizeBytes int  `json:"max_share_size_bytes"`
	MaxFiles          int  `json:"max_files"`
	ChunkSizeBytes    int  `json:"chunk_size_bytes"`
	BurnAfterRead     bool `json:"burn_after_read"`
}

type CreateFileShareRequest struct {
	Slug             string `json:"slug,omitempty"`
	Salt             string `json:"salt,omitempty"`
	KDFParams        string `json:"kdf_params,omitempty"`
	ExpiresInHours   int    `json:"expires_in_hours,omitempty"`
	ExpiresInMinutes int    `json:"expires_in_minutes,omitempty"`
	FileCount        int    `json:"file_count"`
	TotalSizeBytes   int64  `json:"total_size_bytes"`
	BurnAfterRead    bool   `json:"burn_after_read,omitempty"`
	MaxViews         int    `json:"max_views,omitempty"`
	// Recipient seals the share to an agent key (no #k= in the link).
	Recipient *ShareRecipientRequest `json:"recipient,omitempty"`
}

// ShareRecipientRequest is the recipient of a sealed share: the content key
// wrapped (PVWRAP1) to the agent's public key. AgentID names an agent of the
// sender's account; without it the share is sealed to a raw key (--to-key).
type ShareRecipientRequest struct {
	AgentID     string `json:"agent_id,omitempty"`
	Fingerprint string `json:"fingerprint"`
	WrappedKey  string `json:"wrapped_key"`
}

type CreateFileShareResponse struct {
	Slug          string `json:"slug"`
	ExpiresAt     string `json:"expires_at"`
	BurnAfterRead bool   `json:"burn_after_read"`
	MaxViews      *int   `json:"max_views"`
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
	// Sealed shares only (api_version 2).
	WrappedKey           string `json:"wrapped_key"`
	RecipientFingerprint string `json:"recipient_fingerprint"`
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
	MaxViews       *int   `json:"max_views"`
	ViewsRemaining *int   `json:"views_remaining"`
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
	// api_version 2 additions.
	MaxViews              *int           `json:"max_views"`
	ViewsRemaining        *int           `json:"views_remaining"`
	Recipient             *RecipientMeta `json:"recipient"`
	RequiresRecipientAuth bool           `json:"requires_recipient_auth"`
}

// RecipientMeta names the key a sealed share is wrapped to.
type RecipientMeta struct {
	Fingerprint string `json:"fingerprint"`
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
	Message          string `json:"message"`
	Code             string `json:"code"`
	Required         string `json:"required"`
}

type APIRequestError struct {
	Method           string
	Path             string
	StatusCode       int
	Status           string
	ErrorCode        string
	ErrorDescription string
	// Code is the server's machine-readable code when it sends one next to a
	// human-readable "error"; Required names the scope a token lacked.
	Code     string
	Required string
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

// ShareKind tells pastes and file shares apart. Bare slugs and pv://share
// handles leave it empty until the server is asked.
type ShareKind string

const (
	ShareKindUnknown   ShareKind = ""
	ShareKindPaste     ShareKind = "paste"
	ShareKindFileShare ShareKind = "file_share"
)

type ShareReference struct {
	Server string
	Slug   string
	Key    []byte
	Kind   ShareKind
	// Params holds pv://share query parameters other than server (var, agent).
	Params map[string]string
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

// PasteContent is the plaintext of a /p/ paste, identical to the web app's
// PasteContent (frontend/src/types). Field order matters for byte-identical
// ciphertexts: it matches JSON.stringify of the object the web builds.
type PasteContent struct {
	Title        string `json:"title"`
	Body         string `json:"body"`
	RenderMode   string `json:"render_mode"`
	LanguageHint string `json:"language_hint,omitempty"`
}

type CreatePasteRequest struct {
	Ciphertext       string `json:"ciphertext"`
	Nonce            string `json:"nonce"`
	Slug             string `json:"slug,omitempty"`
	Salt             string `json:"salt,omitempty"`
	KDFParams        string `json:"kdf_params,omitempty"`
	ExpiresInHours   int    `json:"expires_in_hours,omitempty"`
	ExpiresInMinutes int    `json:"expires_in_minutes,omitempty"`
	BurnAfterRead    bool   `json:"burn_after_read,omitempty"`
	MaxViews         int    `json:"max_views,omitempty"`
	// Recipient seals the paste to an agent key (no #k= in the link).
	Recipient *ShareRecipientRequest `json:"recipient,omitempty"`
}

type CreatePasteResponse struct {
	Slug      string `json:"slug"`
	ExpiresAt string `json:"expires_at"`
	MaxViews  *int   `json:"max_views"`
}

// PasteMetaResponse describes a paste without consuming a view.
type PasteMetaResponse struct {
	Slug                  string         `json:"slug"`
	CreatedAt             string         `json:"created_at"`
	ExpiresAt             string         `json:"expires_at"`
	BurnAfterRead         bool           `json:"burn_after_read"`
	IsBurned              bool           `json:"is_burned"`
	PasswordProtected     bool           `json:"password_protected"`
	Salt                  string         `json:"salt"`
	KDFParams             string         `json:"kdf_params"`
	MaxViews              *int           `json:"max_views"`
	ViewsRemaining        *int           `json:"views_remaining"`
	Recipient             *RecipientMeta `json:"recipient"`
	RequiresRecipientAuth bool           `json:"requires_recipient_auth"`
}

type PasteMetadata struct {
	ID             string `json:"id"`
	Slug           string `json:"slug"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
	BurnAfterRead  bool   `json:"burn_after_read"`
	IsBurned       bool   `json:"is_burned"`
	ViewCount      int    `json:"view_count"`
	MaxViews       *int   `json:"max_views"`
	ViewsRemaining *int   `json:"views_remaining"`
}

// GetPasteResponse is the consuming GET /api/pastes/:slug.
type GetPasteResponse struct {
	Metadata             PasteMetadata `json:"metadata"`
	Ciphertext           string        `json:"ciphertext"`
	Nonce                string        `json:"nonce"`
	Salt                 string        `json:"salt"`
	KDFParams            string        `json:"kdf_params"`
	WrappedKey           string        `json:"wrapped_key"`
	RecipientFingerprint string        `json:"recipient_fingerprint"`
}

// MeResponse is GET /api/me.
type MeResponse struct {
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Name     string `json:"name"`
	} `json:"user"`
	Auth struct {
		Kind    string     `json:"kind"`
		TokenID string     `json:"token_id,omitempty"`
		Scopes  []string   `json:"scopes"`
		Agent   *AgentInfo `json:"agent,omitempty"`
	} `json:"auth"`
}

type AgentInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type CreateAPITokenRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes,omitempty"`
	// ExpiresInDays is sent as null for a token that never expires.
	ExpiresInDays *int   `json:"expires_in_days"`
	AgentID       string `json:"agent_id,omitempty"`
}

type CreateAPITokenResponse struct {
	ID        string   `json:"id"`
	Token     string   `json:"token"`
	Name      string   `json:"name"`
	Prefix    string   `json:"prefix"`
	Scopes    []string `json:"scopes"`
	AgentID   *string  `json:"agent_id"`
	ExpiresAt *string  `json:"expires_at"`
}

type APITokenSummary struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	Agent      *AgentInfo `json:"agent"`
	CreatedAt  string     `json:"created_at"`
	ExpiresAt  *string    `json:"expires_at"`
	LastUsedAt *string    `json:"last_used_at"`
	RevokedAt  *string    `json:"revoked_at"`
}

type ListAPITokensResponse struct {
	Tokens []APITokenSummary `json:"tokens"`
}

type RevokeAPITokenResponse struct {
	Token APITokenSummary `json:"token"`
}

// AccountShare is one share owned by the account (GET /api/account/shares).
type AccountShare struct {
	ID                   string  `json:"id"`
	ShareType            string  `json:"share_type"`
	Slug                 string  `json:"slug"`
	Status               string  `json:"status"`
	CreatedAt            string  `json:"created_at"`
	ExpiresAt            *string `json:"expires_at"`
	DeletedAt            *string `json:"deleted_at"`
	FirstViewedAt        *string `json:"first_viewed_at"`
	LastViewedAt         *string `json:"last_viewed_at"`
	ViewCount            int     `json:"view_count"`
	BurnAfterRead        bool    `json:"burn_after_read"`
	FileCount            *int    `json:"file_count"`
	TotalSizeBytes       *string `json:"total_size_bytes"`
	IsPasswordProtected  bool    `json:"is_password_protected"`
	CanDelete            bool    `json:"can_delete"`
	MaxViews             *int    `json:"max_views"`
	RecipientFingerprint *string `json:"recipient_fingerprint"`
	RecipientAgentName   *string `json:"recipient_agent_name"`
}

type AccountSharesQuery struct {
	ShareType string
	Status    string
	Slug      string
	Limit     int
	Cursor    string
}

type ListAccountSharesResponse struct {
	Shares     []AccountShare `json:"shares"`
	NextCursor *string        `json:"next_cursor"`
}

type RevokeAccountShareResponse struct {
	Share AccountShare `json:"share"`
}

type AuditActorAgent struct {
	ID   string  `json:"id"`
	Name *string `json:"name"`
}

type AuditEvent struct {
	ID           string           `json:"id"`
	SubjectType  string           `json:"subject_type"`
	SubjectID    *string          `json:"subject_id"`
	Slug         *string          `json:"slug"`
	Event        string           `json:"event"`
	ActorKind    string           `json:"actor_kind"`
	ActorAgent   *AuditActorAgent `json:"actor_agent"`
	ActorTokenID *string          `json:"actor_token_id"`
	Client       *string          `json:"client"`
	IPPrefix     *string          `json:"ip_prefix"`
	CreatedAt    string           `json:"created_at"`
	Details      map[string]any   `json:"details"`
}

type AuditQuery struct {
	Since  string
	Event  string
	Limit  int
	Cursor string
}

type ListAuditEventsResponse struct {
	Events     []AuditEvent `json:"events"`
	NextCursor *string      `json:"next_cursor"`
}

type ListShareEventsResponse struct {
	Events []AuditEvent `json:"events"`
}

// AgentSummary is an agent identity as the server lists it. Fingerprint is
// the server's claim; clients recompute it from PublicKey.
type AgentSummary struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Kind        string  `json:"kind"`
	PublicKey   string  `json:"public_key"`
	Fingerprint string  `json:"fingerprint"`
	CreatedAt   string  `json:"created_at"`
	LastUsedAt  *string `json:"last_used_at"`
	RevokedAt   *string `json:"revoked_at"`
}

type CreateAgentRequest struct {
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

type CreateAgentResponse struct {
	Agent AgentSummary `json:"agent"`
	// TokenBound is true when the API token used is now bound to this agent.
	TokenBound bool `json:"token_bound"`
}

type ListAgentsResponse struct {
	Agents []AgentSummary `json:"agents"`
}

type RevokeAgentResponse struct {
	Agent         AgentSummary `json:"agent"`
	TokensRevoked int          `json:"tokens_revoked"`
}
