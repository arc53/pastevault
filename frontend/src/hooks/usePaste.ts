import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { CreatePasteRequest } from '@/types'

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