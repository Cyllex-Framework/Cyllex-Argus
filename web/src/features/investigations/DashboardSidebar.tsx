import { Link } from 'react-router-dom'
import type { ReactNode } from 'react'
import type { DashboardEntity, DashboardInvestigation } from '../../api/types'

/**
 * Sidebar with a context header: a back link, the threat
 * title in the console-voice (mono) and a compact state line, then collapsible groups (details/summary)
 * of numbered items with a hairline divider between them. The active item carries a thick left bar and
 * a tinted background.
 */

interface Section {
  id: SectionId
  label: string
}

interface Group {
  key: string
  title: string
  sections: readonly Section[]
}

export const GROUPS: readonly Group[] = [
  { key: 'summary', title: 'Summary', sections: [{ id: 'overview', label: 'Overview' }] },
  {
    key: 'intel',
    title: 'Intelligence',
    sections: [
      { id: 'matrix', label: 'ATT&CK matrix' },
      { id: 'graph', label: 'Relationship graph' },
      { id: 'campaigns', label: 'Known campaigns' },
      { id: 'facts', label: 'Facts' },
    ],
  },
  {
    key: 'evidence',
    title: 'Evidence',
    sections: [
      { id: 'documents', label: 'Documents' },
      { id: 'trace', label: 'Pipeline trace' },
    ],
  },
] as const

export const SECTIONS = GROUPS.flatMap((group) => group.sections)

export type SectionId = 'overview' | 'matrix' | 'graph' | 'campaigns' | 'facts' | 'trace' | 'documents'

export const isSectionId = (value: string | null): value is SectionId =>
  SECTIONS.some((section) => section.id === value)

const SECTION_INDEX: Record<SectionId, number> = SECTIONS.reduce((acc, section, index) => {
  acc[section.id] = index + 1
  return acc
}, {} as Record<SectionId, number>)

const pad = (n: number) => n.toString().padStart(2, '0')

function groupOf(section: SectionId): string {
  return GROUPS.find((group) => group.sections.some((s) => s.id === section))?.key ?? 'summary'
}

export function DashboardSidebar({ active, onSelect, badges, narrow, investigation, entity }: {
  active: SectionId
  onSelect: (id: SectionId) => void
  badges: Partial<Record<SectionId, ReactNode>>
  narrow: boolean
  investigation?: DashboardInvestigation
  entity?: DashboardEntity | null
}) {
  if (narrow) {
    return (
      <nav aria-label="Investigation sections" data-layout="pills" className="flex gap-2 overflow-x-auto pb-1">
        {SECTIONS.map(({ id, label }) => {
          const isActive = id === active
          return (
            <button key={id} type="button" aria-current={isActive ? 'page' : undefined} aria-label={label}
              onClick={() => onSelect(id)}
              className={`whitespace-nowrap flex items-center gap-2 px-3 py-1 text-sm border ${
                isActive ? 'border-white bg-gray-700 text-white' : 'border-gray-700 text-gray-300 hover:bg-gray-800'
              }`}>
              <span className="font-mono text-[10px] text-gray-500">{pad(SECTION_INDEX[id])}</span>
              <span>{label}</span>
              {badges[id] !== undefined && <span className="text-xs text-gray-400">{badges[id]}</span>}
            </button>
          )
        })}
      </nav>
    )
  }

  const title = entity?.name ?? investigation?.target ?? 'Investigation'
  const subtitle = entity ? entity.stix_type : `Investigation #${investigation?.id ?? ''}`
  const activeGroup = groupOf(active)
  const counts = investigation?.counts ?? {}
  const totalDocs = Object.values(counts).reduce((a, b) => a + b, 0)

  return (
    <nav aria-label="Investigation sections" data-layout="sidebar"
      className="sticky top-4 w-[280px] shrink-0 self-start text-sm">
      {/* Header: back link, title, state line */}
      <header className="mb-3 border border-gray-800 bg-gray-900/40 p-3">
        <Link to="/investigations"
          className="group inline-flex items-center gap-1 text-xs font-semibold text-gray-400 hover:text-white">
          <span aria-hidden="true" className="transition-transform group-hover:-translate-x-0.5">←</span>
          <span>All investigations</span>
        </Link>
        <div className="mt-2 font-mono text-sm font-bold leading-snug text-gray-100 break-words">{title}</div>
        <div className="mt-0.5 text-[11px] text-gray-500 break-words">{subtitle}</div>
        {investigation && (
          <div className="mt-3 flex items-center justify-between text-[11px] text-gray-400">
            <span>
              {totalDocs} doc{totalDocs === 1 ? '' : 's'} · {investigation.state}
            </span>
          </div>
        )}
      </header>

      {/* Groups as collapsible details, open by default. */}
      {GROUPS.map((group) => (
        <details key={group.key} open className="group/g mb-1.5 border-b border-gray-800 pb-1.5"
          data-active={group.key === activeGroup || undefined}>
          <summary
            className="flex cursor-pointer list-none items-center justify-between gap-2 px-2 py-1.5 text-xs font-bold uppercase tracking-wider text-gray-400 hover:bg-gray-800/60 hover:text-gray-200 [&::-webkit-details-marker]:hidden">
            <span>{group.title}</span>
            <svg className="h-3.5 w-3.5 shrink-0 text-gray-500 transition-transform duration-200 group-open/g:rotate-90"
              viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path d="M7 5l6 5-6 5V5z" />
            </svg>
          </summary>
          <ul className="mt-1 space-y-0.5">
            {group.sections.map((section) => {
              const isActive = section.id === active
              return (
                <li key={section.id}>
                  <button type="button" aria-current={isActive ? 'page' : undefined}
                    aria-label={section.label} onClick={() => onSelect(section.id)}
                    className={`group/i w-full text-left flex items-center gap-2 border-l-2 px-2 py-1.5 leading-snug transition-colors ${
                      isActive
                        ? 'border-white bg-gray-800/70 font-semibold text-white'
                        : 'border-transparent text-gray-400 hover:bg-gray-800/40 hover:text-gray-100'
                    }`}>
                    <span className={`tabular-nums font-mono text-[11px] w-6 ${isActive ? 'text-gray-300' : 'text-gray-500 group-hover/i:text-gray-400'}`}>
                      {pad(SECTION_INDEX[section.id])}
                    </span>
                    <span className="flex-1">{section.label}</span>
                    {badges[section.id] !== undefined && (
                      <span className={`tabular-nums text-[10px] ${isActive ? 'text-gray-200' : 'text-gray-500'}`}>
                        {badges[section.id]}
                      </span>
                    )}
                  </button>
                </li>
              )
            })}
          </ul>
        </details>
      ))}
    </nav>
  )
}
