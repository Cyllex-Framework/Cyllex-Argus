import { useEffect, useRef, useState } from 'react'

/**
 * A centered confirm-before-acting dialog, in the house style (dark panel, dimmed backdrop).
 * Every confirm in the app goes through this so no surface falls back to the browser's native
 * window.confirm / window.prompt (which render as an out-of-place OS dialog).
 *
 * Pass `confirmPhrase` for a destructive type-to-confirm gate (database wipe/import, etc.): the
 * operator must type that exact word before the confirm button enables — the stronger gate the
 * old native prompt gave, now in the framework's own style.
 *
 * Accessibility: role/aria-modal, Escape and backdrop-click cancel, and focus moves to the typed
 * field (when present) or the confirm button so a keyboard user can accept or Escape immediately.
 */
export function ConfirmDialog({
  open, title, confirmLabel, onConfirm, onClose, busy = false, tone = 'primary', confirmPhrase, children,
}: {
  open: boolean
  title: string
  confirmLabel: string
  onConfirm: () => void
  onClose: () => void
  busy?: boolean
  tone?: 'primary' | 'danger'
  confirmPhrase?: string
  children: React.ReactNode
}) {
  const confirmRef = useRef<HTMLButtonElement | null>(null)
  const phraseRef = useRef<HTMLInputElement | null>(null)
  const [typed, setTyped] = useState('')
  const phraseOk = !confirmPhrase || typed === confirmPhrase

  useEffect(() => {
    if (!open) return
    setTyped('')
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape' && !busy) onClose() }
    document.addEventListener('keydown', onKey)
    requestAnimationFrame(() => (confirmPhrase ? phraseRef.current : confirmRef.current)?.focus())
    return () => document.removeEventListener('keydown', onKey)
  }, [open, busy, onClose, confirmPhrase])

  if (!open) return null

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-dialog-title"
      className="fixed inset-0 z-50 flex items-start justify-center p-4 bg-black/60"
      onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose() }}
    >
      <div className="mt-24 w-full max-w-md rounded-lg bg-gray-900 border border-gray-700 shadow-xl p-5 space-y-4">
        <div className="flex items-start justify-between gap-4">
          <h2 id="confirm-dialog-title" className="text-base font-semibold text-white">{title}</h2>
          <button type="button" aria-label="Close" className="text-gray-400 hover:text-white"
            onClick={onClose} disabled={busy}>&times;</button>
        </div>
        <div className="text-sm text-gray-300 space-y-2">{children}</div>
        {confirmPhrase && (
          <label className="block space-y-1">
            <span className="text-xs text-gray-400">
              Type <code className="px-1 rounded bg-gray-800 text-gray-200">{confirmPhrase}</code> to confirm
            </span>
            <input
              ref={phraseRef}
              type="text"
              className="input w-full"
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              disabled={busy}
              autoComplete="off"
              spellCheck={false}
              aria-label={`Type ${confirmPhrase} to confirm`}
              onKeyDown={(event) => { if (event.key === 'Enter' && phraseOk && !busy) onConfirm() }}
            />
          </label>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary btn-sm" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button ref={confirmRef} type="button"
            className={`btn btn-sm ${tone === 'danger' ? 'btn-danger' : 'btn-primary'}`}
            onClick={onConfirm} disabled={busy || !phraseOk}>
            {busy ? 'Working…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
