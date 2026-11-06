import type { Scope } from '../api/types'

const OPTIONS: { value: Scope; label: string }[] = [
  { value: 'everything', label: 'Everything known' },
  { value: 'investigation', label: 'This investigation' },
]

/** Toggle between the whole knowledge base and only what one investigation contributed. */
export function ScopeSwitch({ value, onChange, investigationEmpty = false }: {
  value: Scope
  onChange: (scope: Scope) => void
  /** The investigation contributed nothing about the entity: "This investigation" is disabled and a hint says why. */
  investigationEmpty?: boolean
}) {
  return (
    <div>
      <div className="btn-group">
        {OPTIONS.map(({ value: option, label }) => (
          <button key={option} type="button" className={`btn btn-sm ${value === option ? 'active' : ''}`} aria-pressed={value === option}
            disabled={option === 'investigation' && investigationEmpty} onClick={() => onChange(option)}>
            {label}
          </button>
        ))}
      </div>
      {investigationEmpty && (
        <p className="text-xs text-gray-400 mt-1">This investigation contributed no facts about this entity yet.</p>
      )}
    </div>
  )
}
