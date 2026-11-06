import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { isActiveJob, jobPage, useJobs, useWatchers, type Watcher } from '../api/hooks'
import type { Job } from '../api/types'

/** "in 3h" / "4m ago" — a compact distance from now, good enough for a header glance. */
export function relativeFromNow(iso: string | null, now: number = Date.now()): string {
  if (!iso) return '—'
  const ms = new Date(iso).getTime() - now
  if (Number.isNaN(ms)) return '—'
  const past = ms < 0
  const s = Math.abs(ms) / 1000
  let out: string
  if (s < 60) out = 'under a minute'
  else if (s < 3600) out = `${Math.round(s / 60)}m`
  else if (s < 48 * 3600) out = `${Math.round(s / 3600)}h`
  else out = `${Math.round(s / 86400)}d`
  if (out === 'under a minute') return past ? 'just now' : 'in under a minute'
  return past ? `${out} ago` : `in ${out}`
}

/**
 * Header menu listing standing watchers at a glance: each one's next run (or "paused"), whether it
 * has unseen changes, and when it last ran. It mirrors the TabBar Operations menu (click to toggle,
 * Escape / click-outside to close) so it is keyboard-accessible, not hover-only. Picking a watcher
 * takes the operator to the Watchers page, where its results and change feed live.
 */
export function WatchersMenu() {
  const { data: watchers } = useWatchers()
  const [open, setOpen] = useState(false)
  const container = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()

  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') setOpen(false) }
    const onClick = (event: MouseEvent) => {
      if (!container.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onClick)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onClick)
    }
  }, [open])

  const { data: jobs } = useJobs()
  const list = watchers ?? []
  const unseenTotal = list.reduce((sum, w) => sum + w.unseen_count, 0)

  // A watcher is "running now" when an investigate job tagged with its id is queued or running.
  // useJobs polls every 2s while a job is active, so this stays live with no extra wiring.
  const runningJob = new Map<number, Job>()
  for (const j of jobs ?? []) {
    const wid = j.params.watcher_id
    if (isActiveJob(j) && j.kind === 'investigate' && typeof wid === 'number') runningJob.set(wid, j)
  }
  // Running watchers float to the top of the menu so they are the first thing you see.
  const ordered = [...list].sort((a, b) => Number(runningJob.has(b.id)) - Number(runningJob.has(a.id)))

  const open_watchers = () => { setOpen(false); navigate('/watchers') }
  // Pick a watcher → a running one goes to its live investigation dashboard; otherwise to the
  // threat it monitors (its consolidated investigation), or the Watchers page if it never resolved.
  const go = (w: Watcher) => {
    setOpen(false)
    const job = runningJob.get(w.id)
    if (job) { navigate(jobPage(job)); return }
    navigate(w.entity_id ? `/threats/${encodeURIComponent(w.entity_id)}` : '/watchers')
  }

  return (
    <div className="relative flex" ref={container}>
      <button type="button" aria-haspopup="menu" aria-expanded={open} aria-label="Watchers"
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 text-sm rounded px-2 py-1 border border-gray-700 text-gray-300 hover:border-gray-500 hover:bg-gray-700 hover:text-white active:bg-gray-600 transition-colors">
        <span className="hidden sm:inline">Watchers</span>
        {runningJob.size > 0 && (
          <span data-testid="watchers-running" title={`${runningJob.size} running now`}
            className="flex items-center gap-1 text-[10px] text-emerald-300">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" aria-hidden="true" />
            {runningJob.size}
          </span>
        )}
        {unseenTotal > 0 && (
          <span data-testid="watchers-unseen" className="text-[10px] font-mono rounded-full bg-purple-700 text-white px-1.5">
            {unseenTotal}
          </span>
        )}
        <svg aria-hidden="true" className={`w-3 h-3 transition-transform ${open ? 'rotate-180' : ''}`}
          viewBox="0 0 20 20" fill="currentColor"><path d="M5 7l5 6 5-6H5z" /></svg>
      </button>
      {open && (
        <ul role="menu" aria-label="Watchers list"
          className="absolute right-0 top-full mt-1 w-72 max-h-[70vh] overflow-y-auto border border-gray-700 bg-gray-900 shadow-xl z-50 py-1">
          {list.length === 0 ? (
            <li className="px-3 py-2 text-sm text-gray-400">
              No watchers yet.{' '}
              <button type="button" className="text-purple-400 hover:underline" onClick={open_watchers}>Create one</button>
            </li>
          ) : (
            ordered.map((w) => {
              const running = runningJob.has(w.id)
              return (
              <li key={w.id} role="none">
                <button type="button" role="menuitem" onClick={() => go(w)}
                  className="block w-full text-left px-3 py-2 text-sm hover:bg-gray-800 focus:outline-none focus-visible:bg-gray-800">
                  <div className="flex items-center justify-between gap-2">
                    <span className="min-w-0 flex items-center gap-1.5">
                      {running && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-400 animate-pulse" aria-hidden="true" />}
                      <span className="truncate font-medium text-gray-100" title={w.target}>{w.target}</span>
                    </span>
                    {w.unseen_count > 0 && (
                      <span className="shrink-0 text-[10px] font-mono rounded-full bg-purple-700 text-white px-1.5">
                        {w.unseen_count} new
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-gray-500">
                    {running
                      ? <span className="text-emerald-300">running now…</span>
                      : w.enabled ? `next run ${relativeFromNow(w.next_run_at)}` : 'paused'}
                    {w.last_run_at && ` · last ran ${relativeFromNow(w.last_run_at)}`}
                  </div>
                </button>
              </li>
              )
            })
          )}
          <li role="none" className="border-t border-gray-800 mt-1 pt-1">
            <button type="button" role="menuitem" onClick={open_watchers}
              className="block w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-800">
              Open Watchers →
            </button>
          </li>
        </ul>
      )}
    </div>
  )
}
