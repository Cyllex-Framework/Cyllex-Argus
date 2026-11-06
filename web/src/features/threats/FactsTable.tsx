import { useMemo, useState } from 'react'
import type { Fact } from '../../api/types'
import { AdmiraltyBadge, AnalyticConfidenceBadge, ConfidenceBar, StatusPill } from '../../components/badges'
import { formatDate } from '../../lib/format'

export const factKey = (fact: Fact) => `${fact.subject.id}|${fact.predicate}|${fact.object.id}`

function seen(fact: Fact): string {
  if (!fact.first_seen && !fact.last_seen) return '-'
  if (fact.first_seen === fact.last_seen) return formatDate(fact.first_seen)
  const day = (value: string | null) => (value ? formatDate(value) : '?')
  return `${day(fact.first_seen)} .. ${day(fact.last_seen)}`
}

export function FactsTable({ facts, entityId, selected, onSelect }: {
  facts: Fact[]
  entityId: string
  selected: string | null
  onSelect: (key: string) => void
}) {
  const [predicate, setPredicate] = useState('')
  const [status, setStatus] = useState('')
  const predicates = useMemo(() => [...new Set(facts.map((f) => f.predicate))].sort(), [facts])
  const visible = facts.filter((f) => (!predicate || f.predicate === predicate) && (!status || f.status === status))
  return (
    <>
      <div className="flex gap-3 mb-3">
        <select className="select" aria-label="Filter by relation" value={predicate} onChange={(e) => setPredicate(e.target.value)}>
          <option value="">All relations</option>
          {predicates.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        <select className="select" aria-label="Filter by status" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          <option value="corroborated">corroborated</option>
          <option value="single-source">single-source</option>
          <option value="contested">contested</option>
        </select>
      </div>
      <div className="overflow-x-auto">
      <table className="data-table w-full">
        <thead><tr>
          <th>Relation</th><th>Entity</th><th>Status</th><th>Confidence</th>
          <th title="ICD 203 analytic confidence (HIGH/MODERATE/LOW). Click a row to edit.">ICD&nbsp;203</th>
          <th>Admiralty</th><th>Seen</th><th>Sources</th>
        </tr></thead>
        <tbody>
          {visible.map((fact) => {
            const key = factKey(fact)
            const outgoing = fact.subject.id === entityId
            const other = outgoing ? fact.object : fact.subject
            return (
              <tr key={key} onClick={() => onSelect(key)} aria-selected={selected === key} tabIndex={0}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault()
                    onSelect(key)
                  }
                }}
                className={`cursor-pointer ${selected === key ? 'bg-gray-700/50' : ''}`}>
                <td className="text-gray-400">{outgoing ? fact.predicate : `${fact.predicate} (by)`}</td>
                <td>{other.label}</td>
                <td><StatusPill status={fact.status} /></td>
                <td><ConfidenceBar value={fact.confidence} /></td>
                <td><AnalyticConfidenceBadge level={fact.analytic_confidence} rationale={fact.confidence_rationale} /></td>
                <td><AdmiraltyBadge code={fact.admiralty} /></td>
                <td className="text-xs text-gray-400 whitespace-nowrap">{seen(fact)}</td>
                <td>{fact.source_count}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
      </div>
    </>
  )
}
