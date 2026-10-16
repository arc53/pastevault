import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { CreateFileShareRequest, CreatePasteRequest } from '@/types'

export function useCreatePaste() {
  return useMutation({
    mutationFn: (data: CreatePasteRequest) => api.createPaste(data),
  })
}

// Viewer queries must never refetch on their own: reading a share counts as a
// view and may burn it, and a refetch after a burn would replace the revealed
// content with a 410 error.
const consumingQueryOptions = {
  retry: false,
  staleTime: Infinity,
  refetchOnWindowFocus: false,
  refetchOnReconnect: false,
} as const

export function useGetPasteMeta(slug: string) {
  return useQuery({
    queryKey: ['paste-meta', slug],
    queryFn: () => api.getPasteMeta(slug),
    enabled: !!slug,
    ...consumingQueryOptions,
  })
}

export function useGetPaste(slug: string, enabled = true) {
  return useQuery({
    queryKey: ['paste', slug],
    queryFn: () => api.getPaste(slug),
    enabled: !!slug && enabled,
    ...consumingQueryOptions,
  })
}

export function useGetCapabilities() {
  return useQuery({
    queryKey: ['capabilities'],
    queryFn: () => api.getCapabilities(),
    staleTime: 5 * 60 * 1000,
  })
}

export function useCreateFileShare() {
  return useMutation({
    mutationFn: (data: CreateFileShareRequest) => api.createFileShare(data),
  })
}

export function useGetFileShareMeta(slug: string) {
  return useQuery({
    queryKey: ['file-share-meta', slug],
    queryFn: () => api.getFileShareMeta(slug),
    enabled: !!slug,
    ...consumingQueryOptions,
  })
}

export function useGetFileShare(slug: string, enabled = true) {
  return useQuery({
    queryKey: ['file-share', slug],
    queryFn: () => api.getFileShare(slug),
    enabled: !!slug && enabled,
    ...consumingQueryOptions,
  })
}
