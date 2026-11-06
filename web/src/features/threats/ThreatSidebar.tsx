/**
 * Sidebar for the Threat profile. Mirrors the look-and-feel of DashboardSidebar (the Investigation
 * Dashboard uses it), so the operator sees the same visual grammar on both pages: a context header
 * at the top, collapsible groups of sections below, the active section marked with a thick left bar
 * and tinted background. The grouping differs: this one is about what you can DO with the threat
 * (look at its matrix, enrich an indicator against it), not about the
 * investigation that produced the information.
 */

import { useId } from 'react'

export const SECTION_IDS = [
  'overview',
  'matrix',
  'graph',
  'latest-run',
  'sigma',
  'enrich',
  'identity',
] as const

export type ThreatSectionId = (typeof SECTION_IDS)[number]

export function isThreatSectionId(value: string | null): value is ThreatSectionId {
  return value !== null && (SECTION_IDS as readonly string[]).includes(value)
}

interface Section {
  id: ThreatSectionId
  label: string
  hidden?: boolean
}

interface Group {
  key: string
  title: string
  sections: Section[]
}

interface Props {
  active: ThreatSectionId
  onSelect: (next: ThreatSectionId) => void
  badges?: Partial<Record<ThreatSectionId, string | number | null>>
  narrow?: boolean
  isIdentity?: boolean
}

export function ThreatSidebar({ active, onSelect, badges, narrow, isIdentity }: Props) {
  const groups: Group[] = [
    { key: 'summary', title: 'Summary', sections: [{ id: 'overview', label: 'Overview' }] },
    {
      key: 'intel',
      title: 'Intelligence',
      sections: [
        { id: 'matrix', label: 'ATT&CK matrix' },
        { id: 'graph', label: 'Relationship graph' },
      ],
    },
    {
      key: 'evidence',
      title: 'Evidence',
      sections: [{ id: 'latest-run', label: 'Latest investigation' }],
    },
    {
      key: 'detection',
      title: 'Detection',
      sections: [
        { id: 'sigma', label: 'Sigma rules' },
      ],
    },
    {
      key: 'enrichment',
      title: 'Enrichment',
      sections: [
        { id: 'enrich', label: 'Enrich an indicator' },
        { id: 'identity', label: 'Identity attributes', hidden: !isIdentity },
      ],
    },
  ]
  const nav = (
    <nav aria-label="Threat sections" className="flex-shrink-0">
      {groups.map((g) => (
        <SidebarGroup key={g.key} group={g} active={active} onSelect={onSelect} badges={badges} />
      ))}
    </nav>
  )
  if (narrow) {
    return <div className="mb-2">{nav}</div>
  }
  return (
    <aside className="w-56 flex-shrink-0 sticky top-4 self-start">{nav}</aside>
  )
}

function SidebarGroup({ group, active, onSelect, badges }: {
  group: Group; active: ThreatSectionId; onSelect: (next: ThreatSectionId) => void
  badges?: Partial<Record<ThreatSectionId, string | number | null>>
}) {
  const visible = group.sections.filter((s) => !s.hidden)
  if (visible.length === 0) return null
  const id = useId()
  return (
    <details open className="mb-3 group">
      <summary className="list-none cursor-pointer text-xs font-semibold uppercase tracking-wide text-gray-400 py-1 select-none"
               aria-controls={id}>
        <span className="mr-1 inline-block transition-transform group-open:rotate-90">▸</span>
        {group.title}
      </summary>
      <ul id={id} className="mt-1 border-l border-gray-700 ml-1.5">
        {visible.map((s) => {
          const isActive = s.id === active
          const badge = badges?.[s.id]
          return (
            <li key={s.id}>
              <button type="button" onClick={() => onSelect(s.id)}
                aria-current={isActive ? 'page' : undefined}
                className={[
                  'w-full text-left px-2 py-1.5 text-sm flex items-center justify-between gap-2',
                  isActive
                    ? 'text-white bg-gray-800/70 border-l-2 -ml-[2px] border-white'
                    : 'text-gray-300 hover:text-white hover:bg-gray-800/40 border-l-2 -ml-[2px] border-transparent',
                ].join(' ')}>
                <span className="truncate">{s.label}</span>
                {badge !== null && badge !== undefined && badge !== '' && (
                  <span className="text-xs text-gray-400 tabular-nums">{badge}</span>
                )}
              </button>
            </li>
          )
        })}
      </ul>
    </details>
  )
}
