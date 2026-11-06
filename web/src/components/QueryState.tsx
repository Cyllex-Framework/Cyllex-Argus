import type { ReactNode } from 'react'

export function Loading() {
  return <p className="text-gray-400 text-sm">Loading...</p>
}

export function ErrorCard({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : 'Something went wrong'
  return <div className="card p-5 text-red-400 text-sm" role="alert">{message}</div>
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="text-gray-400 text-sm py-6 text-center">{children}</p>
}
