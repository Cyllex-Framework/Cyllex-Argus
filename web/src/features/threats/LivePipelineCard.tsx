import { type LivePipelineTree, type PipelineDoc, type PipelineStage, useLivePipelineTree } from '../../api/hooks'
import { Card } from '../../components/Card'
import { Loading } from '../../components/QueryState'

/**
 * Live snapshot of a running (or just-finished) investigation attached to this actor.
 * Shows up on the Threat profile for actors that have an investigation whose id is
 * passed in. Data is read by polling `/api/investigations/{id}/live-tree` every 2s
 * while the state is still `running`; polling stops once finished.
 */
export function LivePipelineCard({ investigationId }: { investigationId: number | null }) {
  const { data, error, isLoading } = useLivePipelineTree(investigationId)
  if (investigationId === null) return null
  // Silent degradation: when the endpoint is unreachable (404 during a deploy skew, test
  // environments without the mock), the card simply does not render. The parent page is
  // the one the operator came for; a loud error card next to its real content would be
  // worse UX than quietly dropping this extra view.
  if (error) return null
  return (
    <Card title="Investigation pipeline" actions={<StateChip data={data} loading={isLoading} />}>
      {isLoading ? <Loading /> : data ? <TreeBody data={data} /> : null}
    </Card>
  )
}

function StateChip({ data, loading }: { data: LivePipelineTree | undefined; loading: boolean }) {
  if (loading || !data) return <span className="text-xs text-gray-400">Loading</span>
  const label = data.state.toUpperCase()
  const cls =
    data.state === 'running' ? 'bg-amber-900/30 text-amber-300 border-amber-800'
    : data.state === 'paused' ? 'bg-gray-800 text-gray-300 border-gray-700'
    : 'bg-emerald-900/30 text-emerald-300 border-emerald-800'
  return (
    <span className={`text-[11px] font-semibold tracking-wider px-2 py-0.5 rounded-full border ${cls}`}>
      {label} · {formatElapsed(data.elapsed_secs)}
    </span>
  )
}

function formatElapsed(secs: number): string {
  const m = Math.floor(secs / 60)
  const s = secs % 60
  return m > 0 ? `${m}m ${s}s` : `${s}s`
}

const STAGE_LABEL: Record<PipelineStage['key'], string> = {
  collect: 'Collect', triage: 'Triage', analyze: 'Analyze', validate: 'Validate',
}

function TreeBody({ data }: { data: LivePipelineTree }) {
  const pct = data.totals.docs_analyzed + data.totals.docs_remaining > 0
    ? Math.round((data.totals.docs_analyzed / (data.totals.docs_analyzed + data.totals.docs_remaining)) * 100)
    : 0
  return (
    <div className="space-y-4">
      <ProgressRail stages={data.stages} />
      <div className="flex items-center justify-between text-xs text-gray-400">
        <span className="tabular-nums font-mono">
          {pct}% · {data.totals.docs_analyzed} / {data.totals.docs_analyzed + data.totals.docs_remaining} docs
        </span>
        {data.prompt_version && (
          <span className="font-mono text-[11px] bg-gray-800/60 px-2 py-0.5 rounded">
            {data.prompt_version}
          </span>
        )}
      </div>

      <ul className="space-y-3">
        {data.stages.map((stage) => (
          <li key={stage.key}>
            <div className="flex items-baseline gap-3 flex-wrap">
              <span className={`text-sm font-semibold ${stage.state === 'active' ? 'text-amber-300'
                                                       : stage.state === 'done' ? 'text-emerald-300'
                                                       : 'text-gray-500'}`}>
                {STAGE_LABEL[stage.key]}
              </span>
              <span className="text-xs text-gray-400 tabular-nums font-mono">{stage.summary}</span>
            </div>
            {stage.key === 'analyze' && stage.state === 'active' && data.docs.length > 0 && (
              <DocList docs={data.docs} />
            )}
            {stage.key === 'validate' && (
              <ValidatorPanel v={data.validator} />
            )}
            {stage.key !== 'validate' && stage.latest_reason && stage.state === 'done' && (
              <p className="text-xs italic text-gray-500 mt-1 border-l-2 border-gray-700 pl-2">
                Last decision: &ldquo;{stage.latest_reason}&rdquo;
              </p>
            )}
          </li>
        ))}
      </ul>

      <div className="flex gap-5 flex-wrap text-xs pt-3 border-t border-gray-800">
        <span className="text-[11px] uppercase tracking-wide text-gray-500">Totals</span>
        <span><strong className="font-mono text-gray-100 tabular-nums">{data.totals.claims}</strong>
          <span className="text-gray-400 ml-1">claims</span></span>
        <span><strong className="font-mono text-gray-100 tabular-nums">{data.totals.docs_analyzed}</strong>
          <span className="text-gray-400 ml-1">docs analyzed</span></span>
        <span><strong className="font-mono text-gray-100 tabular-nums">{data.totals.docs_remaining}</strong>
          <span className="text-gray-400 ml-1">docs remaining</span></span>
      </div>
    </div>
  )
}

function ProgressRail({ stages }: { stages: PipelineStage[] }) {
  return (
    <div className="flex items-center gap-0 w-full">
      {stages.map((s, i) => (
        <div key={s.key} className="flex items-center flex-1 min-w-0">
          <span
            aria-label={`${STAGE_LABEL[s.key]}: ${s.state}`}
            className={`w-3 h-3 rounded-full flex-shrink-0 ${
              s.state === 'done' ? 'bg-emerald-500'
              : s.state === 'active' ? 'bg-amber-500 ring-4 ring-amber-500/25'
              : 'bg-gray-600'
            }`}
          />
          {i < stages.length - 1 && (
            <span className={`flex-1 h-0.5 mx-2 min-w-[12px] ${
              stages[i + 1].state === 'done' || stages[i + 1].state === 'active'
                ? 'bg-emerald-600' : 'bg-gray-700'
            }`} />
          )}
        </div>
      ))}
    </div>
  )
}

function DocList({ docs }: { docs: PipelineDoc[] }) {
  // Group: done first, then queued, then failed. Within each: original order.
  const sorted = [...docs].sort((a, b) => {
    const order = { done: 0, running: 1, queued: 2, failed: 3, irrelevant: 4 } as Record<string, number>
    return (order[a.state] ?? 9) - (order[b.state] ?? 9)
  })
  return (
    <ul className="mt-2 ml-2 space-y-1">
      {sorted.map((d) => (
        <li key={d.document_id} className="grid grid-cols-[16px_1fr_auto_auto] gap-3 items-center text-xs
                                           py-1 px-2 rounded hover:bg-gray-800/40">
          <DocStateIcon state={d.state} />
          <span className="truncate min-w-0">
            {d.url ? (
              <a href={d.url} target="_blank" rel="noopener noreferrer"
                 className="text-gray-200 hover:text-cyan-400 hover:underline underline-offset-2">
                {d.title}
              </a>
            ) : (
              <span className="text-gray-200">{d.title}</span>
            )}
          </span>
          <span className={`font-mono tabular-nums text-[11px] ${
            d.state === 'queued' ? 'text-gray-500' : 'text-gray-300'
          }`}>
            {d.state === 'queued' ? 'queued' : d.state === 'failed' ? 'failed' : <><strong className="text-gray-100">{d.facts_count}</strong> facts</>}
          </span>
          <span className={`font-mono tabular-nums text-[11px] text-right ${
            d.state === 'queued' ? 'text-gray-600' : 'text-gray-400'
          }`}>
            {d.elapsed_secs != null ? `${d.elapsed_secs.toFixed(1)}s` : '—'}
          </span>
        </li>
      ))}
    </ul>
  )
}

function DocStateIcon({ state }: { state: PipelineDoc['state'] }) {
  if (state === 'done') return <span aria-label="done" className="text-emerald-400">✓</span>
  if (state === 'running') return <span aria-label="running" className="text-amber-400">◐</span>
  if (state === 'failed') return <span aria-label="failed" className="text-rose-400">✕</span>
  if (state === 'irrelevant') return <span aria-label="irrelevant" className="text-gray-500">—</span>
  return <span aria-label="queued" className="text-gray-500">▸</span>
}

function ValidatorPanel({ v }: { v: LivePipelineTree['validator'] }) {
  const items = [
    { label: 'accepted', value: v.accepted, cls: 'text-emerald-300' },
    { label: 'rejected', value: v.rejected, cls: 'text-rose-300' },
    { label: 'captured-as-sector', value: v.captured_as_sector, cls: 'text-purple-300' },
    { label: 'swapped', value: v.swapped, cls: 'text-gray-300' },
  ]
  return (
    <div className="mt-2 ml-2 space-y-2">
      <div className="flex flex-wrap gap-2">
        {items.map((it) => (
          <span key={it.label} className="inline-flex items-center gap-1.5 text-[11px] px-2 py-0.5
                                          rounded-full bg-gray-800/60 border border-gray-700">
            <strong className={`font-mono tabular-nums ${it.cls}`}>{it.value}</strong>
            <span className="text-gray-400">{it.label}</span>
          </span>
        ))}
      </div>
      {(v.latest_reject || v.latest_capture) && (
        <div className="text-[11px] text-gray-500 space-y-0.5">
          {v.latest_reject && <div><span className="font-mono text-gray-600">reject</span> &nbsp;{v.latest_reject}</div>}
          {v.latest_capture && <div><span className="font-mono text-gray-600">capture</span> {v.latest_capture}</div>}
        </div>
      )}
    </div>
  )
}
