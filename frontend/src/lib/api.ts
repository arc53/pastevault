import {
  AccountShare,
  CapabilitiesResponse,
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
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

async function apiRequest<T>(
  endpoint: string,
  options?: RequestInit
): Promise<T> {
  const url = `${getApiBaseUrl()}${endpoint}`
  
  const response = await fetch(url, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  })

  if (!response.ok) {
    const errorText = await response.text()
    let errorMessage = `HTTP ${response.status}`
    
    try {
      const errorJson = JSON.parse(errorText)
      errorMessage = errorJson.error || errorMessage
    } catch {
      errorMessage = errorText || errorMessage
    }
    
    throw new ApiError(response.status, errorMessage)
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
    const errorText = await response.text()
    let errorMessage = `HTTP ${response.status}`

    try {
      const errorJson = JSON.parse(errorText)
      errorMessage = errorJson.error || errorMessage
    } catch {
      errorMessage = errorText || errorMessage
    }

    throw new ApiError(response.status, errorMessage)
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
