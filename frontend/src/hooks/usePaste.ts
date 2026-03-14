import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { CreateFileShareRequest, CreatePasteRequest } from '@/types'

export function useCreatePaste() {
  return useMutation({
    mutationFn: (data: CreatePasteRequest) => api.createPaste(data),
  })
}

export function useGetPaste(slug: string) {
  return useQuery({
    queryKey: ['paste', slug],
    queryFn: () => api.getPaste(slug),
    enabled: !!slug,
    retry: false,
  })
}

export function useDeletePaste() {
  return useMutation({
    mutationFn: (slug: string) => api.deletePaste(slug),
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

export function useGetFileShare(slug: string) {
  return useQuery({
    queryKey: ['file-share', slug],
    queryFn: () => api.getFileShare(slug),
    enabled: !!slug,
    retry: false,
  })
}
