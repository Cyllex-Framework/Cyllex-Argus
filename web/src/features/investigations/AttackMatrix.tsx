import { useState } from 'react'
import type { FactStatus, ScopeParam, Tactic } from '../../api/types'
import { TechniqueModal } from './TechniqueModal'

const OBSERVED_CELL: Record<FactStatus, string> = {
  corroborated: 'bg-emerald-700/60 text-emerald-100 hover:bg-emerald-700/80',
  'single-source': 'bg-amber-700/60 text-amber-100 hover:bg-amber-700/80',
  contested: 'bg-rose-700/60 text-rose-100 hover:bg-rose-700/80',
}
const SWATCH: Record<FactStatus, string> = {
  corroborated: 'bg-emerald-500', 'single-source': 'bg-amber-500', contested: 'bg-rose-500',
}
const LEGEND_LABEL: Record<FactStatus, string> = {
  corroborated: 'Corroborated', 'single-source': 'Single source', contested: 'Contested',
}
const SUBTECHNIQUE = /^T\d{4}\.\d{3}$/

function Legend() {
  return (
    <ul className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-gray-300" aria-label="Legend">
      {(['corroborated', 'single-source', 'contested'] as const).map((status) => (
        <li key={status} className="flex items-center gap-1.5">
          <span className={`inline-block w-2.5 h-2.5 rounded-full ${SWATCH[status]}`} aria-hidden="true" />
          {LEGEND_LABEL[status]}
        </li>
      ))}
    </ul>
  )
}

/** Observed-only matrix. Only tactics with techniques Argus has recorded for this threat are shown.
 *  Clicking a technique opens the centered TechniqueModal (or fires `onSelect` for legacy callers that
 *  still drive their own citations panel). */
export function AttackMatrix({ tactics, scope, onSelect }: {
  tactics: Tactic[]
  scope?: ScopeParam
  /** Legacy: when provided, matrix clicks fire it instead of opening the modal. */
  onSelect?: (entityId: string) => void
}) {
  const [selected, setSelected] = useState<{ entityId: string; tacticName: string } | null>(null)
  const populated = tactics.filter((tactic) => tactic.techniques.length > 0)

  if (populated.length === 0) {
    return (
      <div className="text-sm text-gray-400">
        No techniques observed yet. Run or extend the investigation to extract claims about ATT&amp;CK techniques.
      </div>
    )
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-3 flex-wrap gap-3">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-400">
          ATT&amp;CK techniques observed
        </h2>
        <Legend />
      </div>
      <div className="overflow-x-auto border border-gray-800">
        <div className="flex min-w-max">
          {populated.map((tactic) => (
            <div key={tactic.id} aria-label={tactic.name}
              className="w-[180px] shrink-0 border-r border-gray-800 last:border-r-0">
              {/* Purple tactic header, sticky when the column scrolls. */}
              <div className="bg-purple-900 border-b-2 border-purple-700 px-2 py-1.5 sticky top-0 z-10">
                <div className="flex items-start justify-between gap-1">
                  <h3 className="text-[11px] font-bold uppercase tracking-wide text-white leading-tight">
                    {tactic.name}
                  </h3>
                  <span data-testid="count-badge" className="text-[10px] font-mono text-purple-200 whitespace-nowrap">
                    {tactic.techniques.length}
                  </span>
                </div>
              </div>
              <div className="max-h-[70vh] overflow-y-auto">
                {tactic.techniques.map((technique) => {
                  const sub = SUBTECHNIQUE.test(technique.external_id)
                  const titleText = `${technique.external_id} ${technique.name} — ${technique.status} · ${technique.sources} source${technique.sources === 1 ? '' : 's'}`
                  return (
                    <button key={technique.id} type="button" title={titleText}
                      onClick={() => (onSelect ? onSelect(technique.id) : setSelected({ entityId: technique.id, tacticName: tactic.name }))}
                      className={`block w-full text-left border-b border-gray-900 focus:outline-none focus-visible:ring-1 focus-visible:ring-white/40 transition-colors ${sub ? 'pl-3 py-1 pr-1.5' : 'px-1.5 py-1'} ${OBSERVED_CELL[technique.status]}`}>
                      <span className="block font-mono text-[10px] leading-tight text-white/80">{technique.external_id}</span>
                      <span className="block text-[11px] leading-tight truncate font-medium" title={technique.name}>
                        {technique.name}
                      </span>
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
      {selected && (
        <TechniqueModal entityId={selected.entityId} tacticName={selected.tacticName} scope={scope}
          onClose={() => setSelected(null)} />
      )}
    </div>
  )
}
