'use client'

import { createAuthClient } from 'better-auth/react'
import { usernameClient } from 'better-auth/client/plugins'

function getAuthBaseUrl() {
  if (typeof window !== 'undefined') {
    if (process.env.NEXT_PUBLIC_API_URL) {
      return `${process.env.NEXT_PUBLIC_API_URL}/auth`
    }

    return `${window.location.origin}/api/auth`
  }

  return `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001/api'}/auth`
}

export const authClient = createAuthClient({
  baseURL: getAuthBaseUrl(),
  fetchOptions: {
    credentials: 'include',
  },
  plugins: [usernameClient()],
})
