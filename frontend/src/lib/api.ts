import { CreatePasteRequest, CreatePasteResponse, GetPasteResponse } from '@/types'

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

export const api = {
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
}

export { ApiError }