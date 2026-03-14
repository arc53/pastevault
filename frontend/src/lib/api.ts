import {
  CapabilitiesResponse,
  CompleteFileShareRequest,
  CreateFileShareRequest,
  CreateFileShareResponse,
  CreatePasteRequest,
  CreatePasteResponse,
  GetFileShareResponse,
  GetPasteResponse,
} from '@/types'

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001/api'

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
  const url = `${API_BASE_URL}${endpoint}`
  
  const response = await fetch(url, {
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
  const url = `${API_BASE_URL}${endpoint}`
  const response = await fetch(url, options)

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

  async getPaste(slug: string): Promise<GetPasteResponse> {
    return apiRequest(`/pastes/${slug}`)
  },

  async deletePaste(slug: string): Promise<{ message: string }> {
    return apiRequest(`/pastes/${slug}`, {
      method: 'DELETE',
    })
  },

  async createFileShare(data: CreateFileShareRequest): Promise<CreateFileShareResponse> {
    return apiRequest('/file-shares', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  },

  async uploadFileShareChunk(
    slug: string,
    fileId: string,
    chunkIndex: number,
    chunk: Uint8Array
  ) {
    await rawRequest(`/file-shares/${slug}/chunks/${fileId}/${chunkIndex}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/octet-stream',
      },
      body: new Uint8Array(chunk),
    })
  },

  async completeFileShare(slug: string, data: CompleteFileShareRequest) {
    return apiRequest<{ slug: string }>(`/file-shares/${slug}/complete`, {
      method: 'POST',
      body: JSON.stringify(data),
    })
  },

  async getFileShare(slug: string): Promise<GetFileShareResponse> {
    return apiRequest(`/file-shares/${slug}`)
  },

  async downloadFileShareChunk(slug: string, fileId: string, chunkIndex: number) {
    const response = await rawRequest(
      `/file-shares/${slug}/chunks/${fileId}/${chunkIndex}`
    )
    const buffer = await response.arrayBuffer()
    return new Uint8Array(buffer)
  },
}

export { ApiError }
