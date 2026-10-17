import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { authClient } from '@/lib/auth-client'

export const agentsQueryKey = ['agents'] as const

// The account's agent identities. Revoked agents are only included on request
// (the account page lists them; the share form never offers them).
export function useAgents({ enabled = true, includeRevoked = false } = {}) {
  return useQuery({
    queryKey: [...agentsQueryKey, includeRevoked ? 'all' : 'active'],
    queryFn: () => api.getAgents(includeRevoked),
    enabled,
    staleTime: 30 * 1000,
  })
}

export function useRevokeAgent() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (agentId: string) => api.revokeAgent(agentId),
    onSettled: async () => {
      // Revoking an agent also revokes the tokens bound to it.
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: agentsQueryKey }),
        queryClient.invalidateQueries({ queryKey: ['api-tokens'] }),
        queryClient.invalidateQueries({ queryKey: ['audit'] }),
      ])
    },
  })
}

// The signed-in user, for pages that must not touch the auth API unless
// accounts are enabled (authClient.useSession() would always fetch).
export function useSessionUser(enabled: boolean) {
  return useQuery({
    queryKey: ['session-user'],
    queryFn: async () => {
      const { data } = await authClient.getSession()
      return data?.user ?? null
    },
    enabled,
    retry: false,
    staleTime: 60 * 1000,
  })
}
