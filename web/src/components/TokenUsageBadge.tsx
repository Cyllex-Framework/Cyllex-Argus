import type { TokenUsage, TokenUsageTotal } from '../api/types'
import { compactNumber, formatCost } from '../lib/format'

const STAGE_LABEL: Record<string, string> = {
  collector: 'Collector', triage: 'Triage', analyst: 'Analyst',
  validator: 'Validator', summary: 'Summary', pipeline: 'Pipeline',
}

/**
 * Compact badge "142k tokens · $0.42" with a per-stage breakdown as its tooltip. Shows nothing when no
 * LLM call was recorded (zero tokens AND zero calls) so a purely deterministic investigation stays silent.
 */
export function TokenUsageBadge({ usage, variant = 'inline' }: {
  usage: TokenUsage | TokenUsageTotal | null | undefined
  variant?: 'inline' | 'card'
}) {
  if (!usage) return null
  const total = 'total' in usage ? usage.total : usage
  if (total.calls === 0 && total.total_tokens === 0) return null

  const stages = 'by_stage' in usage ? usage.by_stage : null
  const tooltip = stages
    ? Object.entries(stages).map(([stage, row]) =>
        `${STAGE_LABEL[stage] ?? stage}: ${compactNumber(row.total_tokens)} tokens · ${formatCost(row.cost_usd)} · ${row.calls} call${row.calls === 1 ? '' : 's'}`,
      ).join('\n')
    : `${total.calls} LLM call${total.calls === 1 ? '' : 's'}`

  if (variant === 'card') {
    return (
      <div className="border border-gray-800 bg-gray-800/30 rounded p-3" title={tooltip}>
        <div className="text-xs uppercase tracking-wide text-gray-500 mb-1">LLM usage</div>
        <div className="flex items-baseline gap-2">
          <span className="text-lg font-mono text-gray-100">{compactNumber(total.total_tokens)}</span>
          <span className="text-xs text-gray-400">tokens</span>
          <span className="text-sm text-gray-300 ml-auto">{formatCost(total.cost_usd)}</span>
        </div>
      </div>
    )
  }

  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-mono text-purple-200 bg-purple-900/40 border border-purple-800 rounded px-2 py-0.5"
      title={tooltip} data-testid="token-usage-badge">
      <span>{compactNumber(total.total_tokens)} tokens</span>
      <span className="text-purple-400">·</span>
      <span>{formatCost(total.cost_usd)}</span>
    </span>
  )
}
