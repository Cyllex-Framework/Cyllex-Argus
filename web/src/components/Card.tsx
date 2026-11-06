import type { ReactNode } from 'react'

export function Card({ title, actions, children, className = '', id }: {
  id?: string
  title?: string
  actions?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section id={id} className={`card p-5 ${className}`}>
      {(title || actions) && (
        <div className="flex items-center justify-between mb-4 gap-4">
          {title && <h2 className="text-xs font-semibold uppercase tracking-wide text-gray-400">{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </section>
  )
}
