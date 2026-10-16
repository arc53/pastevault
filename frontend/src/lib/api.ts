import {
  AccountShare,
  CapabilitiesResponse,
  CreateApiTokenRequest,
  CreateApiTokenResponse,
  ListAgentsResponse,
  ListApiTokensResponse,
  ListAuditEventsResponse,
  ListShareEventsResponse,
  RevokeAgentResponse,
  ApiTokenSummary,
  FulfillSecretRequestBody,
  ListSecretRequestsResponse,
  SecretRequestDetails,
  CompleteFileShareRequest,
  CreateFileShareRequest,
  CreateFileShareResponse,
  CreatePasteRequest,
  CreatePasteResponse,
  FileShareMetaResponse,
  GetFileShareResponse,
  GetPasteResponse,
  ListAccountSharesResponse,
  PasteMetaResponse,
} from '@/types'

function getApiBaseUrl() {
  if (typeof window !== 'undefined') {
    if (process.env.NEXT_PUBLIC_API_URL) {
      return process.env.NEXT_PUBLIC_API_URL
    }

    return `${window.location.origin}/api`
  }

  return process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001/api'
}

class ApiError extends Error {
  // Machine-readable `code` from the error body, when the server sends one
  // (e.g. "recipient_fingerprint_mismatch").
  constructor(public status: number, message: string, public code?: string) {
    super(message)
    this.name = 'ApiError'
  }
}

function toApiError(status: number, errorText: string) {
  let errorMessage = `HTTP ${status}`
  let code: string | undefined

  try {
    const errorJson = JSON.parse(errorText)
    errorMessage = errorJson.message || errorJson.error || errorMessage
    code = typeof errorJson.code === 'string' ? errorJson.code : undefined
    if (!code && typeof errorJson.error === 'string' && /^[a-z_]+$/.test(errorJson.error)) {
      code = errorJson.error
    }
  } catch {
    errorMessage = errorText || errorMessage
  }

  return new ApiError(status, errorMessage, code)
}

async function apiRequest<T>(
  endpoint: string,
  options?: RequestInit
): Promise<T> {
  const url = `${getApiBaseUrl()}${endpoint}`
  
  const response = await fetch(url, {
    credentials: 'include',
    ...options,
    headers: {
      // Only requests with a body are JSON: Fastify rejects an empty body
      // sent as application/json (e.g. DELETE) with 400.
      ...(options?.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...options?.headers,
    },
  })

  if (!response.ok) {
    throw toApiError(response.status, await response.text())
  }

  return response.json()
}

async function rawRequest(
  endpoint: string,
  options?: RequestInit
): Promise<Response> {
  const url = `${getApiBaseUrl()}${endpoint}`
  const response = await fetch(url, {
    credentials: 'include',
    ...options,
  })

  if (!response.ok) {
    throw toApiError(response.status, await response.text())
  }

  return response
}

export const api = {
  async getCapabilities(): Promise<CapabilitiesResponse> {
    return apiRequest('/capabilities')
  },

  async createPaste(data: CreatePasteRequest): Promise<CreatePasteResponse> {
    return apiRequest('/pastes', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  },

  // Does not count as a view and never burns the paste.
  async getPasteMeta(slug: string): Promise<PasteMetaResponse> {
    return apiRequest(`/pastes/${slug}/meta`)
  },

  // Burn-after-read pastes are destroyed by this call.
  async getPaste(slug: string): Promise<GetPasteResponse> {
    return apiRequest(`/pastes/${slug}`)
  },

  async createFileShare(data: CreateFileShareRequest): Promise<CreateFileShareResponse> {
    return apiRequest('/file-shares', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  },

  async uploadFileShareChunk(
    slug: string,
    uploadToken: string,
    fileId: string,
    chunkIndex: number,
    chunk: Uint8Array
  ) {
    await rawRequest(`/file-shares/${slug}/chunks/${fileId}/${chunkIndex}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Upload-Token': uploadToken,
      },
      body: new Uint8Array(chunk),
    })
  },

  async completeFileShare(
    slug: string,
    uploadToken: string,
    data: CompleteFileShareRequest
  ) {
    return apiRequest<{ slug: string }>(`/file-shares/${slug}/complete`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Upload-Token': uploadToken,
      },
      body: JSON.stringify(data),
    })
  },

  // Does not count as a view and never burns the share.
  async getFileShareMeta(slug: string): Promise<FileShareMetaResponse> {
    return apiRequest(`/file-shares/${slug}/meta`)
  },

  // Burn-after-read shares are destroyed by this call; the response carries
  // the download grant needed to fetch their chunks.
  async getFileShare(slug: string): Promise<GetFileShareResponse> {
    return apiRequest(`/file-shares/${slug}`)
  },

  async getAccountShares(filters?: {
    share_type?: AccountShare['share_type']
    status?: AccountShare['status']
  }): Promise<ListAccountSharesResponse> {
    const query = new URLSearchParams()

    if (filters?.share_type) {
      query.set('share_type', filters.share_type)
    }

    if (filters?.status) {
      query.set('status', filters.status)
    }

    const suffix = query.toString() ? `?${query.toString()}` : ''
    return apiRequest(`/account/shares${suffix}`)
  },

  async deleteAccountShare(shareId: string): Promise<{ share: AccountShare }> {
    return apiRequest(`/account/shares/${shareId}`, {
      method: 'DELETE',
    })
  },

  async getShareEvents(shareId: string): Promise<ListShareEventsResponse> {
    return apiRequest(`/account/shares/${encodeURIComponent(shareId)}/events`)
  },

  async getAuditEvents(params: { cursor?: string; limit?: number } = {}): Promise<ListAuditEventsResponse> {
    const query = new URLSearchParams()
    if (params.limit) {
      query.set('limit', String(params.limit))
    }
    if (params.cursor) {
      query.set('cursor', params.cursor)
    }
    const suffix = query.toString() ? `?${query.toString()}` : ''
    return apiRequest(`/account/audit${suffix}`)
  },

  async getAgents(includeRevoked = false): Promise<ListAgentsResponse> {
    return apiRequest(`/agents${includeRevoked ? '?include_revoked=1' : ''}`)
  },

  async revokeAgent(agentId: string): Promise<RevokeAgentResponse> {
    return apiRequest(`/agents/${encodeURIComponent(agentId)}`, {
      method: 'DELETE',
    })
  },

  async getApiTokens(): Promise<ListApiTokensResponse> {
    return apiRequest('/account/tokens')
  },

  async createApiToken(data: CreateApiTokenRequest): Promise<CreateApiTokenResponse> {
    return apiRequest('/account/tokens', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  },

  async revokeApiToken(tokenId: string): Promise<{ token: ApiTokenSummary }> {
    return apiRequest(`/account/tokens/${encodeURIComponent(tokenId)}`, {
      method: 'DELETE',
    })
  },

  // The first lookup marks the request as opened. Session only.
  async getSecretRequestByCode(code: string): Promise<SecretRequestDetails> {
    return apiRequest(`/secret-requests/by-code/${encodeURIComponent(code)}`)
  },

  async fulfillSecretRequest(requestId: string, body: FulfillSecretRequestBody): Promise<{ status: string }> {
    return apiRequest(`/secret-requests/${encodeURIComponent(requestId)}/fulfill`, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  },

  async declineSecretRequest(requestId: string): Promise<{ status: string }> {
    return apiRequest(`/secret-requests/${encodeURIComponent(requestId)}/decline`, {
      method: 'POST',
    })
  },

  async getSecretRequests(): Promise<ListSecretRequestsResponse> {
    return apiRequest('/account/secret-requests')
  },

  async downloadFileShareChunk(
    slug: string,
    fileId: string,
    chunkIndex: number,
    downloadGrant?: string
  ) {
    const response = await rawRequest(
      `/file-shares/${slug}/chunks/${fileId}/${chunkIndex}`,
      downloadGrant ? { headers: { 'X-Download-Grant': downloadGrant } } : undefined
    )
    const buffer = await response.arrayBuffer()
    return new Uint8Array(buffer)
  },
}

export { ApiError }
