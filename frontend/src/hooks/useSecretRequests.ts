import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { SecretRequestDetails } from '@/types'

// How often the /r page re-reads a request: every 3 s while an answer waits
// to be collected (the server allows 120 lookups a minute), slowly while
// pending to notice a cancel or expiry, and not at all once it is final.
function refreshInterval(details: SecretRequestDetails | undefined) {
  switch (details?.status) {
    case 'fulfilled':
      return 3_000
    case 'pending':
      return 15_000
    default:
      return false
  }
}

export function useSecretRequest(code: string, enabled = true) {
  return useQuery({
    queryKey: ['secret-request', code],
    queryFn: () => api.getSecretRequestByCode(code),
    enabled: enabled && Boolean(code),
    staleTime: 0,
    retry: false,
    refetchOnWindowFocus: false,
    refetchInterval: (query) => refreshInterval(query.state.data),
  })
}

export function useSecretRequests(enabled = true) {
  return useQuery({
    queryKey: ['secret-requests'],
    queryFn: () => api.getSecretRequests(),
    enabled,
    staleTime: 10_000,
  })
}
