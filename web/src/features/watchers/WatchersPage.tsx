import { useMemo, useState, type FormEvent } from 'react'
import { ApiError } from '../../api/client'
import {
  useCanWrite, useWatcherChanges, useWatcherMutations, useWatchers,
  type ChangeKind, type Watcher, type WatcherChange,
} from '../../api/hooks'
import { Card } from '../../components/Card'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'

const KIND_LABEL: Record<ChangeKind, string> = {
  new: 'New info', new_source: 'New source', verified: 'Verified', weakened: 'Weakened', contested: 'Contested',
}
// Reuse the framework's status vocabulary: emerald = stronger, amber = weaker, rose = contested.
const KIND_PILL: Record<ChangeKind, string> = {
  new: 'bg-sky-900/40 text-sky-200 border-sky-700/40',
  new_source: 'bg-sky-900/40 text-sky-200 border-sky-700/40',
  verified: 'bg-emerald-900/40 text-emerald-200 border-emerald-700/40',
  weakened: 'bg-amber-900/40 text-amber-200 border-amber-700/40',
  contested: 'bg-rose-900/40 text-rose-200 border-rose-700/40',
}
const WEEKDAYS = [
  { value: 1, label: 'Mon' }, { value: 2, label: 'Tue' }, { value: 3, label: 'Wed' },
  { value: 4, label: 'Thu' }, { value: 5, label: 'Fri' }, { value: 6, label: 'Sat' },
  { value: 0, label: 'Sun' },
]
type Preset = 'daily' | 'weekly' | 'monthly' | 'custom'

function cronFrom(preset: Preset, time: string, weekday: number, day: number, custom: string): string {
  const [h, m] = time.split(':').map((n) => parseInt(n, 10))
  if (preset === 'daily') return `${m} ${h} * * *`
  if (preset === 'weekly') return `${m} ${h} * * ${weekday}`
  if (preset === 'monthly') return `${m} ${h} ${day} * *`
  return custom.trim()
}

function humanWhen(cron: string): string {
  const parts = cron.trim().split(/\s+/)
  if (parts.length !== 5) return cron
  const [m, h, dom, mon, dow] = parts
  const time = `${h.padStart(2, '0')}:${m.padStart(2, '0')}`
  if (dom === '*' && mon === '*' && dow === '*') return `Daily at ${time}`
  if (dom === '*' && mon === '*' && dow !== '*') {
    const name = WEEKDAYS.find((w) => String(w.value) === dow)?.label ?? dow
    return `Weekly on ${name} at ${time}`
  }
  if (dom !== '*' && mon === '*' && dow === '*') return `Monthly on day ${dom} at ${time}`
  return cron
}

function message(error: unknown): string {
  if (error instanceof ApiError) return error.message
  return error instanceof Error ? error.message : String(error)
}

/** The Watchers section: the single home for recurring monitoring. It leads with a discovery-first
 *  feed of what changed on monitored threats, then lists the watchers and a create form that
 *  carries the same run controls (cadence, max docs, concurrency) a one-off investigation has.
 *  Readers see the feed read-only; operators and admins manage. The server enforces role and
 *  ownership; this page surfaces its errors. */
export function WatchersPage() {
  const canWrite = useCanWrite()
  const watchers = useWatchers()

  if (watchers.isLoading) return <Loading />
  if (watchers.error || !watchers.data) return <ErrorCard error={watchers.error} />

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Watchers</h1>
        <p className="text-sm text-gray-400">
          Standing monitors over a threat. Each watcher re-investigates on its own cadence inside
          <code> argus serve</code>, hunts mainly for new information, and brings you only what
          appeared or changed — new facts, newly verified, newly contested. Open a watcher to see
          what it has found.
        </p>
      </div>

      {canWrite && <CreateWatcherCard />}

      <Card title={`Watchers (${watchers.data.length})`}>
        {watchers.data.length === 0 ? (
          <EmptyState>No watchers yet{canWrite ? '. Add one above.' : '.'}</EmptyState>
        ) : (
          <ul className="divide-y divide-gray-700">
            {watchers.data.map((w) => <WatcherRow key={w.id} watcher={w} canWrite={canWrite} />)}
          </ul>
        )}
      </Card>
    </div>
  )
}

function ChangeRow({ change }: { change: WatcherChange }) {
  const claim = [change.subject, change.predicate, change.object].filter(Boolean).join(' ')
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4">
      <div className="flex items-center gap-2 flex-wrap text-sm">
        <span className={`text-xs px-1.5 py-0.5 rounded border ${KIND_PILL[change.kind]}`}>
          {KIND_LABEL[change.kind]}
        </span>
        {change.target && <span className="font-medium text-gray-200">{change.target}</span>}
        <span className="ml-auto text-xs text-gray-500">{new Date(change.detected_at).toLocaleString()}</span>
      </div>
      {claim && <p className="mt-1 text-gray-200">{claim}</p>}
      {(change.from_status || change.to_status) && (
        <p className="mt-1 text-xs text-gray-400">
          {change.from_status ? `${change.from_status} → ` : ''}{change.to_status}
        </p>
      )}
      {change.citation && (
        <blockquote className="mt-2 border-l-2 border-gray-700 pl-3 text-sm italic text-gray-300">
          “{change.citation.quote}”
          <span className="block not-italic text-xs text-gray-500 mt-1">
            {change.citation.publisher} · {change.citation.document_title}
          </span>
        </blockquote>
      )}
    </div>
  )
}

function WatcherRow({ watcher, canWrite }: { watcher: Watcher; canWrite: boolean }) {
  const [open, setOpen] = useState(false)
  const { setEnabled, remove, runNow } = useWatcherMutations()
  const error = setEnabled.error || remove.error || runNow.error
  const meta = [
    watcher.enabled ? 'active' : 'paused',
    humanWhen(watcher.cron_expr),
    watcher.max_docs ? `${watcher.max_docs} docs` : null,
    watcher.concurrency > 1 ? `parallel ${watcher.concurrency}` : null,
  ].filter(Boolean).join(' · ')
  const toggle = () => setOpen((o) => !o)
  // Same look as the top-bar Users/Settings/Log out buttons: bordered, lights up on hover and press.
  const base = 'flex items-center gap-1.5 text-sm rounded px-2.5 py-1 border transition-colors disabled:opacity-60 disabled:cursor-not-allowed'
  const neutral = `${base} border-gray-700 text-gray-300 hover:border-gray-500 hover:bg-gray-700 hover:text-white active:bg-gray-600`
  const danger = `${base} border-gray-700 text-red-300 hover:border-red-500/60 hover:bg-red-900/40 hover:text-red-100 active:bg-red-900/60`
  return (
    <li className="py-3">
      {/* The whole row is the toggle — clicking anywhere on it opens/closes the watcher. The action
          buttons stop propagation so they act without also toggling. */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        {/* The watcher itself is the toggle — clicking anywhere across its row opens/closes it; it
            fills the row and highlights on hover. The action buttons sit beside it. */}
        <button type="button" aria-expanded={open} onClick={toggle}
          className="min-w-0 flex-1 flex items-center gap-3 text-left cursor-pointer rounded px-2 -mx-2 py-1 hover:bg-gray-800/50 focus:outline-none focus-visible:ring-1 focus-visible:ring-white/40">
          <svg aria-hidden="true" className={`w-3.5 h-3.5 shrink-0 text-gray-400 transition-transform ${open ? 'rotate-90' : ''}`}
            viewBox="0 0 20 20" fill="currentColor"><path d="M7 5l6 5-6 5V5z" /></svg>
          <span className={`h-2 w-2 rounded-full ${watcher.enabled ? 'bg-emerald-500' : 'bg-gray-600'}`} aria-hidden="true" />
          <div className="min-w-0">
            <div className="text-base text-white font-semibold truncate" title={watcher.target}>{watcher.target}</div>
            <div className="text-xs text-gray-500">{meta}</div>
          </div>
          {watcher.unseen_count > 0 && (
            <span className="text-xs font-semibold rounded-full bg-indigo-600 text-white px-2 py-0.5">
              {watcher.unseen_count} new
            </span>
          )}
        </button>
        {canWrite && (
          <div className="flex items-center gap-2 flex-wrap">
            <button type="button" className={neutral} disabled={runNow.isPending}
              onClick={() => runNow.mutate(watcher.id)}>
              {runNow.isPending ? 'Running…' : 'Run now'}
            </button>
            <button type="button" className={neutral}
              onClick={() => setEnabled.mutate({ id: watcher.id, enabled: !watcher.enabled })}>
              {watcher.enabled ? 'Pause' : 'Resume'}
            </button>
            <button type="button" aria-label={`Delete watcher ${watcher.target}`} className={danger}
              onClick={() => remove.mutate(watcher.id)}>
              Delete
            </button>
          </div>
        )}
      </div>
      {error && <p role="alert" className="w-full text-red-400 text-xs mt-1">{message(error)}</p>}
      {open && <WatcherChanges watcherId={watcher.id} />}
    </li>
  )
}

/** Lazily-loaded change feed for one watcher — mounted only when its row is expanded, so each
 *  watcher fetches its own changes on demand instead of the page loading one global feed. */
function WatcherChanges({ watcherId }: { watcherId: number }) {
  const changes = useWatcherChanges({ watcher_id: watcherId })
  if (changes.isLoading) return <p className="mt-3 text-xs text-gray-500">Loading changes…</p>
  if (changes.error) return <div className="mt-3"><ErrorCard error={changes.error} /></div>
  const data = changes.data ?? []
  if (data.length === 0) {
    return <p className="mt-3 text-sm text-gray-500" data-testid="no-changes">No changes yet. This watcher reports after its next run.</p>
  }
  // data is newest-first, so Map insertion order keeps the day headers in order.
  const byDay = new Map<string, WatcherChange[]>()
  for (const c of data) {
    const day = new Date(c.detected_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
    const bucket = byDay.get(day)
    if (bucket) bucket.push(c)
    else byDay.set(day, [c])
  }
  return (
    <div className="mt-3 space-y-4 border-t border-gray-700 pt-3">
      {[...byDay.entries()].map(([day, items]) => (
        <div key={day} data-testid="day-group" className="space-y-3">
          <h3 className="text-xs uppercase tracking-wide text-gray-500">{day}</h3>
          {items.map((c) => <ChangeRow key={c.id} change={c} />)}
        </div>
      ))}
    </div>
  )
}

function CreateWatcherCard() {
  const { create } = useWatcherMutations()
  const [target, setTarget] = useState('')
  const [preset, setPreset] = useState<Preset>('daily')
  const [time, setTime] = useState('08:00')
  const [weekday, setWeekday] = useState(1)
  const [day, setDay] = useState(1)
  const [custom, setCustom] = useState('0 8 * * *')
  const [maxDocs, setMaxDocs] = useState('')
  const [concurrency, setConcurrency] = useState(1)

  const cronExpr = useMemo(
    () => cronFrom(preset, time, weekday, day, custom), [preset, time, weekday, day, custom],
  )

  const submit = (event: FormEvent) => {
    event.preventDefault()
    create.mutate({
      target: target.trim(),
      cron_expr: cronExpr,
      max_docs: maxDocs.trim() ? parseInt(maxDocs, 10) : undefined,
      concurrency,
    }, { onSuccess: () => setTarget('') })
  }

  return (
    <Card title="New watcher">
      <form onSubmit={submit} className="space-y-3">
        <label className="block space-y-1">
          <span className="text-sm text-gray-300">Target</span>
          <input className="input w-full" value={target} onChange={(e) => setTarget(e.target.value)}
            placeholder="e.g. APT29" required />
        </label>

        <div className="flex items-end gap-3 flex-wrap">
          <label className="space-y-1">
            <span className="block text-sm text-gray-300">When</span>
            <select className="input" value={preset} onChange={(e) => setPreset(e.target.value as Preset)}>
              <option value="daily">Daily at HH:MM</option>
              <option value="weekly">Weekly on &lt;day&gt; at HH:MM</option>
              <option value="monthly">Monthly on day N at HH:MM</option>
              <option value="custom">Custom cron</option>
            </select>
          </label>
          {preset !== 'custom' && (
            <label className="space-y-1">
              <span className="block text-sm text-gray-300">Time</span>
              <input type="time" className="input" value={time} onChange={(e) => setTime(e.target.value)} />
            </label>
          )}
          {preset === 'weekly' && (
            <label className="space-y-1">
              <span className="block text-sm text-gray-300">Day</span>
              <select className="input" value={weekday} onChange={(e) => setWeekday(Number(e.target.value))}>
                {WEEKDAYS.map((d) => <option key={d.value} value={d.value}>{d.label}</option>)}
              </select>
            </label>
          )}
          {preset === 'monthly' && (
            <label className="space-y-1">
              <span className="block text-sm text-gray-300">Day of month</span>
              <input type="number" min={1} max={31} className="input w-20" value={day}
                onChange={(e) => setDay(Math.max(1, Math.min(31, Number(e.target.value) || 1)))} />
            </label>
          )}
          {preset === 'custom' && (
            <label className="space-y-1 flex-1">
              <span className="block text-sm text-gray-300">Cron (5 fields: m h dom mon dow)</span>
              <input className="input w-full font-mono" placeholder="0 8 * * *" value={custom}
                onChange={(e) => setCustom(e.target.value)} />
            </label>
          )}
        </div>

        <div className="flex items-end gap-3 flex-wrap">
          <label className="space-y-1">
            <span className="block text-sm text-gray-300">Max docs (optional)</span>
            <input type="number" min={1} max={200} className="input w-28" placeholder="default"
              value={maxDocs} onChange={(e) => setMaxDocs(e.target.value)} />
          </label>
          <label className="space-y-1">
            <span className="block text-sm text-gray-300">Concurrency</span>
            <input type="number" min={1} max={16} className="input w-24" value={concurrency}
              onChange={(e) => setConcurrency(Math.max(1, Math.min(16, Number(e.target.value) || 1)))} />
          </label>
        </div>

        <p className="text-xs text-gray-500">
          Will fire as <code className="mono">{cronExpr}</code> ({humanWhen(cronExpr)}).
        </p>

        {create.error && <p role="alert" className="text-sm text-red-400">{message(create.error)}</p>}

        <button type="submit" className="btn btn-primary" disabled={create.isPending || !target.trim()}>
          {create.isPending ? 'Creating…' : 'Create watcher'}
        </button>
      </form>
    </Card>
  )
}
