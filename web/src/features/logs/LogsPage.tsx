import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useLogs } from '../../api/hooks'
import type { Job, JobState, LogEvent } from '../../api/types'
import { Card } from '../../components/Card'
import { JobStatePill } from '../../components/badges'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'
import { compactNumber, formatDateTime } from '../../lib/format'
import { decisionLabel } from '../investigations/PipelineTrace'

const KINDS: { value: Job['kind']; label: string }[] = [
  { value: 'investigate', label: 'Investigate' },
  { value: 'resume', label: 'Resume' },
  { value: 'ingest', label: 'Ingest' },
  { value: 'attack_update', label: 'ATT&CK update' },
  { value: 'recompute', label: 'Recompute' },
]
const STATES: JobState[] = ['queued', 'running', 'finished', 'paused', 'failed']
const RANGES = [
  { value: '24h', label: 'Last 24 h', hours: 24 },
  { value: '1h', label: 'Last hour', hours: 1 },
  { value: 'all', label: 'All time', hours: null },
] as const
type Range = (typeof RANGES)[number]['value']

const AGENTS = [
  { stage: 'collector', label: 'Collector', about: 'Searches and downloads source documents for the target.' },
  { stage: 'triage', label: 'Triage', about: 'Decides whether a document is about the target and worth analysing.' },
  { stage: 'analyst', label: 'Analyst', about: 'Extracts structured claims and their supporting quotes from a document.' },
  { stage: 'validator', label: 'Validator', about: 'Checks each claim against its quote and rejects what the text does not support.' },
  { stage: 'pipeline', label: 'Pipeline', about: 'Records unexpected failures of the pipeline itself.' },
] as const
const PER_AGENT = 30

const sinceFor = (range: Range): string | undefined => {
  const hours = RANGES.find((r) => r.value === range)?.hours
  return hours ? new Date(Date.now() - hours * 3_600_000).toISOString() : undefined
}

function formatDuration(ms: number | null): string {
  if (ms === null) return '-'
  if (ms < 1000) return `${ms} ms`
  const seconds = ms / 1000
  return seconds < 60 ? `${seconds.toFixed(1)} s` : `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`
}

const tone = (decision: string) =>
  decision === 'failed' || decision === 'rejected' ? 'text-red-400' : decision === 'triaged-out' ? 'text-gray-400' : 'text-green-400'

/** Sums tokens and cost across the currently displayed events, grouped by stage. */
function TokenUsageSummary({ events }: { events: LogEvent[] }) {
  const summary = useMemo(() => {
    const byStage = new Map<string, { calls: number; tokens: number; cost: number }>()
    let anyCall = false
    for (const e of events) {
      const tokens = (e.input_tokens ?? 0) + (e.output_tokens ?? 0)
      if (tokens === 0 && !e.cost_usd) continue
      anyCall = true
      const row = byStage.get(e.stage) ?? { calls: 0, tokens: 0, cost: 0 }
      row.calls += 1
      row.tokens += tokens
      row.cost += e.cost_usd ?? 0
      byStage.set(e.stage, row)
    }
    if (!anyCall) return null
    const total = { calls: 0, tokens: 0, cost: 0 }
    for (const row of byStage.values()) {
      total.calls += row.calls; total.tokens += row.tokens; total.cost += row.cost
    }
    return { byStage, total }
  }, [events])

  if (summary === null) return null
  return (
    <section aria-label="LLM usage in this time range"
      className="mb-5 border border-gray-800 bg-gray-800/30 rounded p-3 flex items-center gap-4 flex-wrap">
      <div>
        <div className="text-xs uppercase tracking-wide text-gray-500">Total LLM usage</div>
        <div className="font-mono text-lg text-gray-100">
          {compactNumber(summary.total.tokens)} <span className="text-xs text-gray-400">tokens</span>
          <span className="text-sm text-gray-300 ml-3">
            {summary.total.cost > 0 ? `$${summary.total.cost.toFixed(2)}` : 'free'}
          </span>
          <span className="text-xs text-gray-500 ml-3">{summary.total.calls} call{summary.total.calls === 1 ? '' : 's'}</span>
        </div>
      </div>
      <ul className="flex items-center gap-3 flex-wrap text-xs text-gray-400 ml-auto">
        {[...summary.byStage.entries()].sort().map(([stage, row]) => {
          const agent = AGENTS.find((a) => a.stage === stage)
          return (
            <li key={stage} className="font-mono">
              <span className="text-gray-300">{agent?.label ?? stage}:</span>{' '}
              {compactNumber(row.tokens)} · {row.cost > 0 ? `$${row.cost.toFixed(2)}` : 'free'}
            </li>
          )
        })}
      </ul>
    </section>
  )
}

function EventRow({ event }: { event: LogEvent }) {
  const tokens = (event.input_tokens ?? 0) + (event.output_tokens ?? 0)
  return (
    <li className="text-sm">
      <span className="text-gray-500 mr-2">{formatDateTime(event.created_at)}</span>
      <Link to={`/investigations/${event.investigation_id}/dashboard`} className="text-purple-400 hover:underline mr-2">
        {event.investigation_target}
      </Link>
      {event.document_id !== null && (
        <Link to={`/documents/${event.document_id}`} className="text-purple-400 hover:underline mr-2">
          {event.document_title || `Document #${event.document_id}`}
        </Link>
      )}
      <span className={tone(event.decision)}>{decisionLabel(event.decision)}</span>
      {event.reason && <span className="text-gray-400 ml-1">({event.reason})</span>}
      {tokens > 0 && <span className="text-xs text-gray-500 ml-2">{tokens.toLocaleString()} tokens</span>}
    </li>
  )
}

export function LogsPage() {
  const [kind, setKind] = useState<Job['kind'] | ''>('')
  const [state, setState] = useState<JobState | ''>('')
  const [range, setRange] = useState<Range>('24h')
  // Fixed when the preset is picked, so the query key stays stable between refreshes.
  const [since, setSince] = useState<string | undefined>(() => sinceFor('24h'))
  const { data, error, isLoading } = useLogs({ kind, state, since })
  if (isLoading) return <Loading />
  if (error || !data) return <ErrorCard error={error} />
  return (
    <div className="space-y-6">
      <Card title="Jobs">
        <div className="flex gap-3 mb-4">
          <select className="select" aria-label="Filter by kind" value={kind} onChange={(e) => setKind(e.target.value as Job['kind'] | '')}>
            <option value="">All kinds</option>
            {KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
          </select>
          <select className="select" aria-label="Filter by state" value={state} onChange={(e) => setState(e.target.value as JobState | '')}>
            <option value="">All states</option>
            {STATES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="select" aria-label="Time range" value={range}
            onChange={(e) => { const next = e.target.value as Range; setRange(next); setSince(sinceFor(next)) }}>
            {RANGES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
          </select>
        </div>
        {data.jobs.length === 0 ? (
          <EmptyState>No jobs match these filters. Jobs are kept only while the server runs.</EmptyState>
        ) : (
          <table className="data-table w-full">
            <thead><tr><th>Kind</th><th>State</th><th>Started</th><th>Duration</th><th>Message</th></tr></thead>
            <tbody>
              {data.jobs.map((job) => (
                <tr key={job.id}>
                  <td className="text-sm">{KINDS.find((k) => k.value === job.kind)?.label ?? job.kind}</td>
                  <td><JobStatePill state={job.state} /></td>
                  <td className="text-xs text-gray-400">{formatDateTime(job.started_at)}</td>
                  <td className="text-xs text-gray-400">{formatDuration(job.duration_ms)}</td>
                  <td className="text-xs text-gray-400">{job.message ?? '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <Card title="Agent events">
        <TokenUsageSummary events={data.events} />
        <ul className="text-xs text-gray-400 mb-4 space-y-0.5" aria-label="What each agent does">
          {AGENTS.map((a) => <li key={a.stage}><span className="text-gray-300">{a.label}</span>: {a.about}</li>)}
        </ul>
        {data.events.length === 0 ? (
          <EmptyState>No agent events in this time range. Run an investigation to see the agents at work.</EmptyState>
        ) : (
          <div className="space-y-5">
            {AGENTS.map((agent) => {
              const events = data.events.filter((e) => e.stage === agent.stage).slice(0, PER_AGENT)
              return (
                <section key={agent.stage} aria-label={agent.label}>
                  <h3 className="text-sm font-semibold mb-2">{agent.label} <span className="text-xs text-gray-500 font-normal">({events.length})</span></h3>
                  {events.length === 0 ? (
                    <p className="text-xs text-gray-500">No events.</p>
                  ) : (
                    <ul className="space-y-1">{events.map((e) => <EventRow key={e.id} event={e} />)}</ul>
                  )}
                </section>
              )
            })}
          </div>
        )}
      </Card>
    </div>
  )
}
