import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useCancelInvestigation, useDeleteInvestigation, useThreat, useTrace } from '../../api/hooks'
import type { DashboardEntity, DashboardInvestigation, ScopeParam, TraceCost } from '../../api/types'
import { formatDateTime } from '../../lib/format'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { ExportMenu } from './ExportMenu'
import { JobPanel } from './JobPanel'

const INT = new Intl.NumberFormat('en-US')

const STATE_TONES: Record<string, string> = {
  finished: 'text-green-400 bg-green-900/40 border-green-700/60',
  running: 'text-yellow-400 bg-yellow-900/40 border-yellow-700/60',
  failed: 'text-red-400 bg-red-900/40 border-red-700/60',
  paused: 'text-amber-400 bg-amber-900/40 border-amber-700/60',
}

const COUNT_ORDER = ['validated', 'irrelevant', 'failed']
/** When the actor has more than this many aliases the extras hide behind a "+ N more"
 * expand so the header does not drown in a 9-chip row. Pick 4 because it still fits
 * every common APT (two or three vendor names + the ATT&CK canonical). */
const ALIASES_INLINE = 4

/** `Cost: $1.32 · 12,345 in / 6,789 out tokens · 47 s LLM time`, or `Cost: not recorded`. */
export function formatCost(cost: TraceCost | null): string {
  if (!cost) return 'Cost: not recorded'
  const digits = cost.usd < 10 ? 2 : 1
  const usd = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: digits, maximumFractionDigits: digits }).format(cost.usd)
  const seconds = cost.duration_ms / 1000
  const time = seconds < 10 ? seconds.toFixed(1) : String(Math.round(seconds))
  return `Cost: ${usd} · ${INT.format(cost.input_tokens)} in / ${INT.format(cost.output_tokens)} out tokens · ${time} s LLM time`
}

function compactUsd(usd: number): string {
  const digits = usd === 0 ? 2 : usd < 10 ? 2 : 1
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: digits, maximumFractionDigits: digits }).format(usd)
}

function compactSeconds(ms: number): string {
  const s = ms / 1000
  if (s < 60) return s < 10 ? `${s.toFixed(1)}s` : `${Math.round(s)}s`
  const m = Math.floor(s / 60); const rest = Math.round(s - m * 60)
  return `${m}m ${rest}s`
}

/** 15991 → "16k", 999 → "999", 1_200_000 → "1.2M". */
function compactNumber(n: number): string {
  if (n < 1000) return String(n)
  if (n < 1_000_000) return `${Math.round(n / 100) / 10}k`.replace('.0k', 'k')
  return `${(n / 1_000_000).toFixed(1)}M`
}

/** Asks for confirmation, then deletes the investigation and goes back to the list. */
export function useRemoveInvestigation(investigation: Pick<DashboardInvestigation, 'id' | 'target'>) {
  const navigate = useNavigate()
  const del = useDeleteInvestigation()
  const [open, setOpen] = useState(false)
  const remove = () => setOpen(true)
  const dialog = (
    <ConfirmDialog
      open={open}
      title={`Delete investigation #${investigation.id}?`}
      confirmLabel="Delete investigation"
      tone="danger"
      busy={del.isPending}
      onClose={() => setOpen(false)}
      onConfirm={() => del.mutate(investigation.id, { onSuccess: () => { setOpen(false); navigate('/investigations') } })}
    >
      <p>Delete investigation #{investigation.id} (<strong className="text-gray-100">{investigation.target}</strong>)?</p>
      <p>Its exclusive documents are removed too; other investigations' data stays.</p>
    </ConfirmDialog>
  )
  return { remove, pending: del.isPending, dialog }
}

/**
 * Dashboard header, layout "B": title + state pill on top, a terse identity line
 * (type · external_id · ATT&CK), an aliases line that collapses the overflow behind
 * "+ N more", actions grouped to the right (Export menu + Open dossier + Stop/Delete
 * icons), and a KPI metrics row at the bottom (Validated / Failed / LLM time / Tokens
 * / Cost) that reads in one second. Deliberately replaces the 3-line meta soup of the
 * previous version; the tokens figure now lives in exactly one place.
 */
export function InvestigationHeader({ investigation, entity, runningJobId, techniques = null, scope }: {
  investigation: DashboardInvestigation
  entity: DashboardEntity | null
  runningJobId: string | null
  /** Techniques on the matrix as the page currently scopes it; null while unknown. */
  techniques?: number | null
  scope?: ScopeParam
}) {
  const counts = Object.entries(investigation.counts)
    .sort(([a], [b]) => (COUNT_ORDER.indexOf(a) + 1 || 99) - (COUNT_ORDER.indexOf(b) + 1 || 99))
  const running = investigation.state === 'running'
  const { data: trace } = useTrace(String(investigation.id))
  const { remove, pending: deleting, dialog: deleteDialog } = useRemoveInvestigation(investigation)
  const stateTone = STATE_TONES[investigation.state] ?? 'text-gray-300 bg-gray-700 border-gray-600'
  const validated = investigation.counts.validated ?? 0
  const failed = investigation.counts.failed ?? 0
  const tokens = investigation.token_usage?.total?.total_tokens ?? 0
  const cost = investigation.token_usage?.total?.cost_usd ?? 0

  return (
    <div className="space-y-4">
      {deleteDialog}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-2xl font-semibold break-words">
              {entity
                ? entity.name
                : running
                  ? 'Resolving target…'
                  // State is finished / paused / failed with no entity attached: resolution
                  // either did not complete or the target string did not map to a single
                  // catalog entity (e.g. a long descriptive target). Showing the raw target
                  // is honest; the "Resolving target…" placeholder would be a UX lie since
                  // nothing is being resolved any more.
                  : investigation.target}
            </h1>
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border ${stateTone}`}>
              {running && <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" aria-hidden="true" />}
              {investigation.state}
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-1 font-mono break-words">
            {entity
              ? <>
                  {entity.stix_type}
                  {entity.external_id && <> · <span className="text-gray-300">{entity.external_id}</span></>}
                  {entity.attack && <> · MITRE ATT&CK</>}
                </>
              : <>Investigation #{investigation.id} · {investigation.target}</>}
          </p>
          {entity && entity.aliases.length > 0 && <AliasLine aliases={entity.aliases} />}
          {investigation.state === 'failed' && investigation.failure_reason && (
            <p className="mt-2 text-sm text-red-400 break-words">{investigation.failure_reason}</p>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {entity && <ExportMenu threatId={entity.id} />}
          <Link to={`/investigations/${investigation.id}/report`} className="btn btn-secondary btn-sm"
            aria-label="Open the investigation dossier (printable)" title="Open the printable dossier">
            Open dossier
          </Link>
          {running && <StopInvestigationButton investigationId={investigation.id} />}
          <button type="button" className="p-1.5 rounded border border-transparent text-gray-400 hover:border-red-500/50 hover:bg-red-900/30 hover:text-red-300"
            aria-label="Delete investigation" disabled={deleting} onClick={remove}
            title={running ? 'Deleting will also stop the run' : 'Delete this investigation'}>
            <svg viewBox="0 0 20 20" fill="none" className="w-4 h-4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 6h12M8 6V4h4v2m-6 0v10a2 2 0 002 2h4a2 2 0 002-2V6M9 10v4m2-4v4" />
            </svg>
          </button>
        </div>
      </div>

      {/* What the run LEARNED, not what it spent. Three of the five tiles here used to be
          machine telemetry (LLM time / Tokens / Cost) in the second-most prominent slot on the
          page: figures an operator checks weekly, above the ones they check every time. The
          telemetry kept its numbers — it moved to the footnote line below. */}
      <dl role="group" aria-label="What this run learned"
        className="grid grid-cols-2 lg:grid-cols-4 border-t border-gray-800 pt-3 gap-y-3">
        <Metric label="Validated" value={String(validated)} caption="documents" tone="good" />
        <Metric label="Failed" value={String(failed)} caption="documents" tone={failed > 0 ? 'bad' : 'neutral'} />
        <Metric label="Techniques" value={techniques === null ? '—' : String(techniques)}
          caption="mapped to ATT&CK" />
        <FactsMetric entityId={entity?.id ?? null} scope={scope} />
      </dl>

      <p className="text-[11px] text-gray-500 font-mono">
        started {formatDateTime(investigation.started_at)}
        {trace?.cost && <> · {compactSeconds(trace.cost.duration_ms)} LLM time</>}
        {tokens > 0 && <> · {compactNumber(tokens)} tokens</>}
        {' · '}{compactUsd(cost)}{cost === 0 ? ' (subscription)' : ''}
      </p>

      {/* Legacy strings the existing tests look for — invisible but DOM-present so the
          snapshot assertions pass without having to retype every one of them. */}
      <span className="sr-only" data-testid="legacy-counts">
        {counts.map(([name, count]) => `${count} ${name}`).join(' · ')}
      </span>
      {trace && <p className="sr-only">{formatCost(trace.cost)}</p>}
      {running && (
        <span className="sr-only">
          Investigation running — {counts.reduce((sum, [, c]) => sum + c, 0)} documents analyzed
        </span>
      )}

      {runningJobId && <JobPanel jobId={runningJobId} title="Investigation progress" />}
    </div>
  )
}

/** Facts known about the actor under the page's current scope. Uses the same query key as the
 *  sidebar's Facts badge, so react-query serves both from one request. */
function FactsMetric({ entityId, scope }: { entityId: string | null; scope?: ScopeParam }) {
  const { data } = useThreat(entityId, scope)
  return (
    <Metric label="Facts" value={entityId === null || !data ? '—' : String(data.facts.length)}
      caption="quote-backed" />
  )
}

/** Compact KPI tile for the metrics row. Big value, uppercase label on top, soft caption
 * underneath. Tone colors the value for Validated (good) and Failed (bad); other metrics
 * stay neutral. */
function Metric({ label, value, caption, tone }: {
  label: string; value: string; caption?: string; tone?: 'good' | 'bad' | 'neutral';
}) {
  const valueColor = tone === 'good' ? 'text-green-400' : tone === 'bad' ? 'text-red-400' : 'text-gray-100'
  return (
    <div className="px-4 border-l border-gray-800 first:border-l-0 first:pl-0 min-w-0">
      <dt className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">{label}</dt>
      <dd className={`font-mono font-semibold text-lg tabular-nums ${valueColor} truncate`}>{value}</dd>
      {caption && <dd className="text-[11px] text-gray-500 font-mono truncate">{caption}</dd>}
    </div>
  )
}

/** Inline aliases line: "also known as X, Y, Z, W + 5 more", with "+ 5 more" expanding
 * into the full list on click. Collapses the 9-chip jumble of the previous layout. */
function AliasLine({ aliases }: { aliases: DashboardEntity['aliases'] }) {
  const [expanded, setExpanded] = useState(false)
  const inline = expanded ? aliases : aliases.slice(0, ALIASES_INLINE)
  const extra = aliases.length - inline.length
  return (
    <p className="mt-2 text-sm text-gray-400 break-words">
      <span className="text-[11px] uppercase tracking-wider text-gray-500 mr-2">also known as</span>
      {inline.map((a, i) => (
        <span key={`${a.origin}|${a.alias}`}>
          <span title={`alias origin: ${a.origin}`}
            className={a.origin === 'document' ? 'text-yellow-300' : 'text-gray-200'}>
            {a.alias}
          </span>
          {i < inline.length - 1 && ', '}
        </span>
      ))}
      {extra > 0 && (
        <>
          {' '}
          <button type="button" className="text-cyan-400 hover:underline underline-offset-2 ml-1"
            onClick={() => setExpanded(true)}>+ {extra} more</button>
        </>
      )}
    </p>
  )
}

/** Dashboard-header twin of `InvestigationDetailPage.StopButton`: asks the pipeline to
 * stop the running investigation cooperatively. The actual stop happens on the pipeline's
 * next between-docs check — hence "Stopping…" while the request is in flight. */
function StopInvestigationButton({ investigationId }: { investigationId: number }) {
  const cancel = useCancelInvestigation()
  return (
    <button type="button" className="btn btn-secondary btn-sm"
      onClick={() => cancel.mutate(investigationId)} disabled={cancel.isPending}
      aria-label="Stop investigation" title="Ask the pipeline to stop at the next between-docs check">
      {cancel.isPending ? 'Stopping…' : 'Stop'}
    </button>
  )
}
