import type { ReactNode } from 'react'

const HTTP = /^https?:\/\//i

/** Links only for http(s) URLs; anything else (local file names, odd schemes) renders as plain text. */
export function ExternalLink({ href, children }: { href: string | null | undefined; children?: ReactNode }) {
  if (!href) return null
  if (!HTTP.test(href)) return <span className="break-all text-gray-400">{children ?? href}</span>
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="text-purple-400 hover:underline break-all">
      {children ?? href}
    </a>
  )
}
