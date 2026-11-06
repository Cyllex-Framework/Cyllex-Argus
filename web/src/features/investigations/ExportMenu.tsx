import { useEffect, useRef, useState } from 'react'
import { downloadFile } from '../../api/download'
import type { Tlp } from '../../api/types'

interface ExportKind {
  label: string
  query: string
  extension: string
  title?: string
}

const EXPORTS: ExportKind[] = [
  { label: 'Markdown', query: 'format=markdown', extension: 'md' },
  {
    label: 'Markdown + AI summary', query: 'format=markdown&summary=1', extension: 'md',
    title: 'Adds an executive summary written by Claude (uses your subscription and takes a moment).',
  },
  { label: 'STIX 2.1', query: 'format=stix', extension: 'stix.json' },
]

const TLP_CAP_OPTIONS: readonly { value: '' | Tlp; label: string }[] = [
  { value: '', label: 'No TLP cap (export everything)' },
  { value: 'clear', label: 'TLP:CLEAR (strictest — only unclassified sources)' },
  { value: 'green', label: 'TLP:GREEN (community-wide)' },
  { value: 'amber', label: 'TLP:AMBER (organization + clients)' },
  { value: 'amber-strict', label: 'TLP:AMBER+STRICT (organization only)' },
  { value: 'red', label: 'TLP:RED (recipients only)' },
] as const

/**
 * Compact Export dropdown for the investigation dashboard header. Collapses the three
 * export shapes (Markdown / Markdown+AI / STIX) + the TLP cap selector into a single
 * "Export" button so the header reads cleanly, without losing any of the controls
 * `ExportButtons` offers on the Threat profile. Buttons are mounted only when the menu
 * is open — a closed menu is three fewer elements the operator's eye has to parse.
 */
export function ExportMenu({ threatId }: { threatId: string }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [tlpCap, setTlpCap] = useState<'' | Tlp>('')
  const root = useRef<HTMLDivElement>(null)
  const base = `/api/threats/${encodeURIComponent(threatId)}/export`

  useEffect(() => {
    if (!open) return
    const close = (event: MouseEvent) => {
      if (root.current && !root.current.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [open])

  async function run(kind: ExportKind) {
    setBusy((current) => [...current, kind.label])
    setError(null)
    try {
      const q = tlpCap ? `?${kind.query}&tlp_cap=${tlpCap}` : `?${kind.query}`
      await downloadFile(`${base}${q}`, `threat.${kind.extension}`)
    } catch (failure) {
      setError(`${kind.label} export failed: ${failure instanceof Error ? failure.message : 'unknown error'}`)
    } finally {
      setBusy((current) => current.filter((label) => label !== kind.label))
    }
  }

  const anyRunning = busy.length > 0

  return (
    <div ref={root} className="relative inline-block">
      <button type="button" className="btn btn-secondary btn-sm inline-flex items-center gap-1"
        aria-haspopup="menu" aria-expanded={open} aria-busy={anyRunning || undefined}
        onClick={() => setOpen((v) => !v)}>
        {anyRunning ? 'Exporting…' : 'Export'}
        <span aria-hidden="true" className="text-xs opacity-60">▾</span>
      </button>
      {open && (
        <div role="menu" aria-label="Export options"
          className="absolute right-0 top-full mt-1 w-72 z-20 rounded-md border border-gray-700
                     bg-gray-800 shadow-lg p-2 flex flex-col gap-1">
          {EXPORTS.map((kind) => {
            const running = busy.includes(kind.label)
            return (
              <button key={kind.label} type="button" role="menuitem"
                className="text-left px-3 py-2 rounded hover:bg-gray-700/60 text-sm text-gray-100
                           disabled:opacity-50 flex items-center justify-between gap-2"
                title={kind.title} disabled={running} aria-busy={running || undefined}
                onClick={() => void run(kind)}>
                <span>{kind.label}</span>
                {running && <span className="text-xs text-gray-400">downloading…</span>}
              </button>
            )
          })}
          <div className="border-t border-gray-700 pt-2 mt-1">
            <label className="text-[11px] text-gray-400 block mb-1 px-1">TLP cap</label>
            <select className="select text-xs w-full" aria-label="TLP cap for export"
              value={tlpCap} onChange={(event) => setTlpCap(event.target.value as '' | Tlp)}>
              {TLP_CAP_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </div>
          {error && <p role="alert" className="text-xs text-red-400 px-2 pt-1">{error}</p>}
        </div>
      )}
    </div>
  )
}
