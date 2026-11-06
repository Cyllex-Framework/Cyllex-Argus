import { useState, type ReactNode } from 'react'
import { downloadFile } from '../../api/download'
import { DownloadIcon } from '../../components/Icons'
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
    title: 'Adds an executive summary written by Claude (uses your subscription and takes a moment)',
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
 * Export buttons. The API needs the token header, which a plain download link cannot send, so each export is fetched
 * and then saved; while one runs its button is busy (the AI summary can take a while), and a failure shows inline
 * instead of saving the error as the file. The TLP cap selector strips citations from publishers above the cap and
 * omits facts left with no evidence; the exported file's header reports the cap applied.
 */
export function ExportButtons({ threatId, leading }: { threatId: string; leading?: ReactNode }) {
  const [busy, setBusy] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [tlpCap, setTlpCap] = useState<'' | Tlp>('')
  const base = `/api/threats/${encodeURIComponent(threatId)}/export`

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

  return (
    <div className="flex flex-col items-end gap-2">
      <div className="flex gap-2 flex-wrap justify-end items-center">
        {leading}
        {EXPORTS.map((kind) => {
          const running = busy.includes(kind.label)
          return (
            <button key={kind.label} type="button" className="btn btn-secondary btn-sm flex items-center gap-1"
              title={kind.title} disabled={running} aria-busy={running || undefined} onClick={() => void run(kind)}>
              <DownloadIcon className={`w-4 h-4${running ? ' animate-pulse' : ''}`} /> {kind.label}
            </button>
          )
        })}
      </div>
      <select
        className="select text-xs"
        aria-label="TLP cap for export"
        value={tlpCap}
        onChange={(event) => setTlpCap(event.target.value as '' | Tlp)}
      >
        {TLP_CAP_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
      <p role="status" className="text-xs text-gray-400">
        {busy.length > 0 && `Preparing ${busy.join(', ')}...`}
      </p>
      {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
    </div>
  )
}
