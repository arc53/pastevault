'use client'

import Link from 'next/link'
import { UserRound } from 'lucide-react'
import { authClient } from '@/lib/auth-client'
import { Button } from '@/components/ui/button'
import { useGetCapabilities } from '@/hooks/usePaste'

export function AccountLink({ compact = false }: { compact?: boolean }) {
  const { data: capabilities, isPending } = useGetCapabilities()

  if (isPending || capabilities?.auth?.enabled === false) {
    return null
  }

  return <EnabledAccountLink compact={compact} />
}

function EnabledAccountLink({ compact }: { compact: boolean }) {
  const { data: session, isPending } = authClient.useSession()
  const label =
    !isPending && session?.user
      ? session.user.username || session.user.name || 'Account'
      : 'Account'

  return (
    <Button asChild variant="outline" size={compact ? 'sm' : 'default'}>
      <Link href="/account">
        <UserRound className="h-4 w-4" />
        <span>{label}</span>
      </Link>
    </Button>
  )
}
