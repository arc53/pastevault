import { useQuery } from '@tanstack/react-query'
import { ApiError, api } from '@/lib/api'
import { SecretRequestDetails } from '@/types'

// How often the /r page re-reads a request: every 3 s while an answer waits
// to be collected (the server allows 120 lookups a minute), slowly while
// pending to notice a cancel or expiry, and not at all once it is final.
// After a failed read the next one waits for the server's Retry-After (or
// 30 s on a 429 without one).
const RATE_LIMIT_BACKOFF_MS = 30_000

function errorDelay(error: unknown): number | null {
  if (!(error instanceof ApiError)) {
    return null
  }
  if (error.retryAfterSeconds !== undefined) {
    return Math.max(1_000, error.retryAfterSeconds * 1_000)
  }
  return error.status === 429 ? RATE_LIMIT_BACKOFF_MS : null
}

function refreshInterval(details: SecretRequestDetails | undefined, error: unknown) {
  let interval: number | false
  switch (details?.status) {
    case 'fulfilled':
      interval = 3_000
      break
    case 'pending':
      interval = 15_000
      break
    default:
      return false
  }
  const backoff = errorDelay(error)
  return backoff ? Math.max(interval, backoff) : interval
}

export function useSecretRequest(code: string, enabled = true) {
  return useQuery({
    queryKey: ['secret-request', code],
    queryFn: () => api.getSecretRequestByCode(code),
    enabled: enabled && Boolean(code),
    staleTime: 0,
    // One retry for network or server errors (not for 4xx answers), after
    // the server's Retry-After or a short backoff. Cached data stays on
    // screen meanwhile: the page shows an inline "retrying" notice.
    retry: (failureCount, error) =>
      failureCount < 1 && !(error instanceof ApiError && error.status >= 400 && error.status < 500 && error.status !== 429),
    retryDelay: (attempt, error) => errorDelay(error) ?? Math.min(1_000 * 2 ** attempt, 8_000),
    refetchOnWindowFocus: false,
    refetchInterval: (query) => refreshInterval(query.state.data, query.state.error),
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
