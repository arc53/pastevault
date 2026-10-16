import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { AccountShare, CreateApiTokenRequest } from '@/types'

export function useAccountShares(filters?: {
  share_type?: AccountShare['share_type']
  status?: AccountShare['status']
}, enabled = true) {
  return useQuery({
    queryKey: ['account-shares', filters?.share_type || 'all', filters?.status || 'all'],
    queryFn: () => api.getAccountShares(filters),
    enabled,
  })
}

export function useDeleteAccountShare() {
  return useMutation({
    mutationFn: (shareId: string) => api.deleteAccountShare(shareId),
  })
}

export function useShareEvents(shareId: string, enabled = true) {
  return useQuery({
    queryKey: ['share-events', shareId],
    queryFn: () => api.getShareEvents(shareId),
    enabled,
    staleTime: 10 * 1000,
  })
}

const AUDIT_PAGE_SIZE = 20

export function useAuditLog(enabled = true) {
  return useInfiniteQuery({
    queryKey: ['audit'],
    queryFn: ({ pageParam }) =>
      api.getAuditEvents({ limit: AUDIT_PAGE_SIZE, cursor: pageParam || undefined }),
    initialPageParam: '',
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    enabled,
    staleTime: 10 * 1000,
  })
}

export function useApiTokens(enabled = true) {
  return useQuery({
    queryKey: ['api-tokens'],
    queryFn: () => api.getApiTokens(),
    enabled,
  })
}

export function useCreateApiToken() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: CreateApiTokenRequest) => api.createApiToken(data),
    onSettled: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['api-tokens'] }),
        queryClient.invalidateQueries({ queryKey: ['audit'] }),
      ])
    },
  })
}

export function useRevokeApiToken() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (tokenId: string) => api.revokeApiToken(tokenId),
    onSettled: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['api-tokens'] }),
        queryClient.invalidateQueries({ queryKey: ['audit'] }),
      ])
    },
  })
}
