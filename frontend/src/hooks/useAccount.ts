import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { AccountShare } from '@/types'

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
