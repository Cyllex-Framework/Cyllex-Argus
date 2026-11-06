import { useEffect, useState } from 'react'
import { useMispServers, useSaveMispServers, useTestMispServer } from '../../api/hooks'
import type { MispServer, SourceTestResult } from '../../api/types'
import { Card } from '../../components/Card'
import { ErrorCard, Loading } from '../../components/QueryState'

const MASK_VALUE = '••••••••'

/** Empty server row for the "Add server" button. */
function emptyServer(): MispServer {
  return { name: '', url: '', api_key: '', env_api_key: '', timestamp_days: 180, enabled: true }
}

/**
 * UI for the `[[misp]]` list in argus.toml.
 *
 * Each row has a masked API key input (focusing it clears the mask so the next keystroke
 * REPLACES the stored key rather than appending to "••••••••" — the same pattern as the
 * Anthropic / OpenAI inputs in the LLM card). The whole list is saved atomically; a
 * per-row "Test" button issues one `/events/restSearch` call to confirm reachability
 * without leaving the Settings page.
 */
export function MispServersCard() {
  const { data, error, isLoading } = useMispServers()
  const save = useSaveMispServers()
  const test = useTestMispServer()
  const [rows, setRows] = useState<MispServer[]>([])
  const [testResults, setTestResults] = useState<Record<number, SourceTestResult>>({})

  useEffect(() => {
    if (data) setRows(data.servers.map((s) => ({ ...s })))
  }, [data])

  if (isLoading) return <Loading />
  if (error || !data) return <ErrorCard error={error} />

  const update = (index: number, patch: Partial<MispServer>) => {
    setRows((prev) => prev.map((row, i) => (i === index ? { ...row, ...patch } : row)))
  }

  const addRow = () => setRows((prev) => [...prev, emptyServer()])
  const removeRow = (index: number) => {
    setRows((prev) => prev.filter((_, i) => i !== index))
    setTestResults((prev) => {
      const next = { ...prev }
      delete next[index]
      return next
    })
  }

  const onSave = () => {
    // Trim strings before sending so a trailing space in the name doesn't become part of the publisher label.
    const cleaned = rows.map((row) => ({
      ...row, name: row.name.trim(), url: row.url.trim(),
      api_key: row.api_key, env_api_key: row.env_api_key.trim(),
    }))
    save.mutate(cleaned)
  }

  const onTest = async (index: number) => {
    const result = await test.mutateAsync(rows[index]).catch((err: Error) => ({ ok: false, error: err.message }))
    setTestResults((prev) => ({ ...prev, [index]: result }))
  }

  return (
    <Card
      title="MISP servers"
      actions={
        <div className="flex gap-2">
          <button type="button" className="btn btn-ghost btn-sm" onClick={addRow}>Add server</button>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={save.isPending}
            onClick={onSave}
          >
            {save.isPending ? 'Saving…' : 'Save MISP servers'}
          </button>
        </div>
      }
    >
      <p className="text-xs text-gray-400 mb-4">
        Each MISP server adds its matching Events to the Collector line-up alongside RSS, TAXII
        and web search. Argus only pulls Events whose <code className="mono">info</code> or tags
        mention the target, then extracts link-shaped Attributes (<code className="mono">link</code>,{' '}
        <code className="mono">url</code>, <code className="mono">uri</code>) as candidate URLs.
      </p>
      {save.error && <p className="text-sm text-red-400 mb-3" role="alert">{save.error.message}</p>}
      {rows.length === 0 ? (
        <p className="text-sm text-gray-400">No MISP servers configured. Click "Add server" to start.</p>
      ) : (
        <div className="space-y-5">
          {rows.map((row, index) => (
            <ServerRow
              key={index}
              row={row}
              testing={test.isPending}
              result={testResults[index]}
              onChange={(patch) => update(index, patch)}
              onRemove={() => removeRow(index)}
              onTest={() => onTest(index)}
            />
          ))}
        </div>
      )}
    </Card>
  )
}


function ServerRow({
  row, testing, result, onChange, onRemove, onTest,
}: {
  row: MispServer
  testing: boolean
  result: SourceTestResult | undefined
  onChange: (patch: Partial<MispServer>) => void
  onRemove: () => void
  onTest: () => void
}) {
  return (
    <div className="border border-gray-700 rounded p-3 bg-gray-800/50">
      <div className="grid grid-cols-2 gap-3">
        <label className="block">
          <span className="text-xs text-gray-400">Name (shown as publisher: <code className="mono">MISP:&lt;name&gt;</code>)</span>
          <input
            type="text"
            className="input w-full"
            value={row.name}
            onChange={(e) => onChange({ name: e.target.value })}
            placeholder="CIRCL OSINT"
          />
        </label>
        <label className="block">
          <span className="text-xs text-gray-400">Base URL</span>
          <input
            type="url"
            className="input w-full"
            value={row.url}
            onChange={(e) => onChange({ url: e.target.value })}
            placeholder="https://misppriv.circl.lu"
          />
        </label>
        <label className="block">
          <span className="text-xs text-gray-400">API key (leave masked to keep)</span>
          <input
            type="password"
            className="input w-full"
            value={row.api_key}
            onFocus={(e) => { if (e.target.value === MASK_VALUE) onChange({ api_key: '' }) }}
            onChange={(e) => onChange({ api_key: e.target.value })}
            placeholder="(none)"
            autoComplete="new-password"
          />
        </label>
        <label className="block">
          <span className="text-xs text-gray-400">Env var for key (preferred)</span>
          <input
            type="text"
            className="input w-full"
            value={row.env_api_key}
            onChange={(e) => onChange({ env_api_key: e.target.value })}
            placeholder="CIRCL_MISP_TOKEN"
          />
        </label>
        <label className="block">
          <span className="text-xs text-gray-400">Window (days, blank = unlimited)</span>
          <input
            type="number"
            min={1}
            className="input w-full"
            value={row.timestamp_days ?? ''}
            onChange={(e) => onChange({ timestamp_days: e.target.value === '' ? null : Number(e.target.value) })}
          />
        </label>
        <label className="flex items-center gap-2 self-end pb-1">
          <input
            type="checkbox"
            checked={row.enabled}
            onChange={(e) => onChange({ enabled: e.target.checked })}
          />
          <span className={row.enabled ? 'text-emerald-400' : 'text-gray-400'}>
            {row.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </label>
      </div>
      <div className="mt-3 flex items-center gap-3">
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          disabled={testing || !row.url.trim()}
          onClick={onTest}
        >
          Test connection
        </button>
        <button type="button" className="btn btn-ghost btn-sm text-red-400" onClick={onRemove}>
          Remove
        </button>
        {result && (
          <span className={`text-xs ${result.ok ? 'text-emerald-400' : 'text-red-400'}`}>
            {result.ok
              ? `OK — ${result.events_sampled ?? 0} event(s) sampled`
              : `Failed: ${result.error ?? 'unknown error'}`}
          </span>
        )}
      </div>
    </div>
  )
}
