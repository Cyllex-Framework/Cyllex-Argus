import { useRef, useState } from 'react'
import { ApiError, apiFetch } from '../../api/client'
import { downloadFile } from '../../api/download'
import { Card } from '../../components/Card'
import { ConfirmDialog } from '../../components/ConfirmDialog'

/**
 * Export, import or wipe the Argus database. Destructive operations ask twice and send an explicit
 * confirm header; the backend rejects both when any job is active. After import or wipe the user is
 * told to restart Argus because the running SQLiteStore wraps the old file.
 */
export function DatabaseCard() {
  const fileInput = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState<'export' | 'import' | 'wipe' | null>(null)
  const [message, setMessage] = useState<{ tone: 'ok' | 'error'; text: string } | null>(null)
  // Destructive confirms run through the framework ConfirmDialog, not the browser's native prompt.
  const [pendingImport, setPendingImport] = useState<File | null>(null)
  const [wipeOpen, setWipeOpen] = useState(false)
  const say = (tone: 'ok' | 'error', text: string) => setMessage({ tone, text })

  const exportDb = async () => {
    setBusy('export')
    setMessage(null)
    try {
      // Server names the file argus-<timestamp>.db; preserve that filename from Content-Disposition.
      await downloadFile('/api/admin/db/export', 'argus.db')
      say('ok', 'Download started.')
    } catch (failure) {
      say('error', `Export failed: ${failure instanceof Error ? failure.message : 'unknown error'}`)
    } finally {
      setBusy(null)
    }
  }

  const runImport = async (file: File) => {
    setBusy('import')
    setMessage(null)
    try {
      const body = new FormData()
      body.append('file', file)
      const result = await apiFetch<{ message: string }>('/api/admin/db/import', {
        method: 'POST', body, headers: { 'X-Argus-Confirm': 'yes' },
      })
      say('ok', result.message)
    } catch (failure) {
      say('error', failure instanceof ApiError ? failure.message : `Import failed: ${failure instanceof Error ? failure.message : 'unknown error'}`)
    } finally {
      setBusy(null)
      setPendingImport(null)
    }
  }

  const runWipe = async () => {
    setBusy('wipe')
    setMessage(null)
    try {
      const result = await apiFetch<{ message: string }>('/api/admin/db', {
        method: 'DELETE', headers: { 'X-Argus-Confirm': 'yes' },
      })
      say('ok', result.message)
    } catch (failure) {
      say('error', failure instanceof ApiError ? failure.message : `Wipe failed: ${failure instanceof Error ? failure.message : 'unknown error'}`)
    } finally {
      setBusy(null)
      setWipeOpen(false)
    }
  }

  return (
    <Card title="Database">
      <div className="space-y-3 text-sm">
        <p className="text-gray-400">
          Export a consistent snapshot of the Argus DB, replace it with a backup, or wipe it entirely.
          Import and wipe refuse to run while a job is active, and both ask the browser to restart Argus
          afterwards because the running process keeps the old database handle open.
        </p>
        <div className="flex flex-wrap gap-2">
          <button type="button" className="btn btn-secondary btn-sm" disabled={busy !== null}
            onClick={exportDb}>
            {busy === 'export' ? 'Preparing…' : 'Export (.db)'}
          </button>
          <button type="button" className="btn btn-secondary btn-sm" disabled={busy !== null}
            onClick={() => fileInput.current?.click()}>
            {busy === 'import' ? 'Uploading…' : 'Import (.db)…'}
          </button>
          <input ref={fileInput} type="file" accept=".db,.sqlite,.sqlite3,application/octet-stream" hidden
            aria-label="Database file"
            onChange={(event) => {
              const file = event.target.files?.[0]
              event.target.value = ''
              if (file) setPendingImport(file)
            }} />
          <button type="button" className="btn btn-secondary btn-sm text-red-400" disabled={busy !== null}
            onClick={() => setWipeOpen(true)}>
            {busy === 'wipe' ? 'Wiping…' : 'Wipe database'}
          </button>
        </div>
        {message && (
          <p role={message.tone === 'error' ? 'alert' : 'status'}
            className={`text-sm break-words ${message.tone === 'error' ? 'text-red-400' : 'text-green-400'}`}>
            {message.text}
          </p>
        )}
      </div>

      <ConfirmDialog
        open={pendingImport !== null}
        title="Replace the database?"
        confirmLabel="Replace database"
        tone="danger"
        confirmPhrase="REPLACE"
        busy={busy === 'import'}
        onClose={() => setPendingImport(null)}
        onConfirm={() => { if (pendingImport) void runImport(pendingImport) }}
      >
        <p>Replace the current database with <strong className="text-gray-100 break-all">{pendingImport?.name}</strong>?</p>
        <p>
          Everything in the current Argus DB will be overwritten. Running jobs must have finished first, and
          you will need to restart Argus afterwards because the running process keeps the old handle open.
        </p>
      </ConfirmDialog>

      <ConfirmDialog
        open={wipeOpen}
        title="Delete the entire database?"
        confirmLabel="Delete everything"
        tone="danger"
        confirmPhrase="DELETE"
        busy={busy === 'wipe'}
        onClose={() => setWipeOpen(false)}
        onConfirm={() => void runWipe()}
      >
        <p>
          Every investigation, document, claim, assessment and pipeline event will be gone. The ATT&amp;CK
          catalog has to be re-downloaded afterwards, and you will need to restart Argus.
        </p>
      </ConfirmDialog>
    </Card>
  )
}
