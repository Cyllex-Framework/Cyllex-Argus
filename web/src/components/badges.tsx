import type { ReactNode } from 'react'
import type { AssessmentStatus, JobState } from '../api/types'

const TONES = { neutral: 'badge-gray', info: 'badge-purple', warn: 'badge-yellow', danger: 'badge-red', success: 'badge-green' } as const

export function Badge({ tone = 'neutral', children }: { tone?: keyof typeof TONES; children: ReactNode }) {
  return <span className={`badge ${TONES[tone]}`}>{children}</span>
}

const PILL = 'px-2 py-1 rounded text-xs whitespace-nowrap'
const STATUS_TONES: Record<AssessmentStatus, string> = {
  corroborated: 'bg-green-900/50 text-green-400',
  'single-source': 'bg-gray-700 text-gray-300',
  contested: 'bg-red-900/50 text-red-400',
}

export function StatusPill({ status }: { status: AssessmentStatus }) {
  return <span className={`${PILL} ${STATUS_TONES[status] ?? STATUS_TONES['single-source']}`}>{status}</span>
}

const STAGE_TONES: Record<string, string> = {
  validated: 'bg-green-900/50 text-green-400',
  failed: 'bg-red-900/50 text-red-400',
  irrelevant: 'bg-gray-700 text-gray-400',
  triaged: 'bg-blue-900/50 text-blue-400',
  collected: 'bg-yellow-900/50 text-yellow-400',
}

export function StagePill({ stage }: { stage: string }) {
  return <span className={`${PILL} ${STAGE_TONES[stage] ?? 'bg-gray-700 text-gray-300'}`}>{stage}</span>
}

const JOB_TONES: Record<JobState, string> = {
  queued: 'bg-gray-700 text-gray-300',
  running: 'bg-blue-900/50 text-blue-400',
  finished: 'bg-green-900/50 text-green-400',
  paused: 'bg-yellow-900/50 text-yellow-400',
  failed: 'bg-red-900/50 text-red-400',
}

export function JobStatePill({ state }: { state: JobState | string }) {
  return <span className={`${PILL} ${JOB_TONES[state as JobState] ?? 'bg-gray-700 text-gray-300'}`}>{state}</span>
}

export function AdmiraltyBadge({ code }: { code: string }) {
  return (
    <span className="mono text-xs px-1.5 py-0.5 rounded bg-gray-700 text-gray-200"
      title="Admiralty code: source reliability (A-F) and information credibility (1-6)">
      {code}
    </span>
  )
}

const ICD203_TONES: Record<string, string> = {
  high: 'bg-emerald-900/60 text-emerald-200 border border-emerald-700/60',
  moderate: 'bg-amber-900/60 text-amber-200 border border-amber-700/60',
  low: 'bg-rose-900/60 text-rose-200 border border-rose-700/60',
}

export function AnalyticConfidenceBadge({ level, rationale }: {
  level: string | null | undefined
  rationale?: string | null
}) {
  if (!level) return <span className="text-xs text-gray-500">-</span>
  const tone = ICD203_TONES[level] ?? 'bg-gray-700 text-gray-200'
  const title = rationale
    ? `ICD 203 analytic confidence: ${level.toUpperCase()}. Rationale: ${rationale}`
    : `ICD 203 analytic confidence: ${level.toUpperCase()}. Derived from numeric confidence + status.`
  return (
    <span className={`mono text-xs px-1.5 py-0.5 rounded ${tone}`} title={title}>
      {level.toUpperCase()}
    </span>
  )
}

export function ConfidenceBar({ value }: { value: number }) {
  const width = Math.max(0, Math.min(100, value))
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-gray-700 rounded" role="meter" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}
        aria-label="Confidence">
        <div className="h-1.5 rounded" style={{ width: `${width}%`, background: 'var(--accent-color)' }} />
      </div>
      <span className="text-xs text-gray-300">{value}</span>
    </div>
  )
}
