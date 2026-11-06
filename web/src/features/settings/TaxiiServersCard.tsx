import { useEffect, useState } from 'react'
import { useSaveTaxiiServers, useTaxiiServers, useTestTaxiiServer } from '../../api/hooks'
import type { SourceTestResult, TaxiiServer } from '../../api/types'
import { Card } from '../../components/Card'
import { ErrorCard, Loading } from '../../components/QueryState'

const MASK_VALUE = '••••••••'

function emptyServer(): TaxiiServer {
  return {
    name: '', url: '', collection: '',
    api_key: '', env_api_key: '',
    username: '', password: '',
    added_after_days: 180,
    enabled: true,
  }
}

/**
 * UI for the `[[taxii]]` list in argus.toml.
 *
 * TAXII supports three auth shapes: Bearer token (preferred via env), Bearer in toml, or
 * HTTP Basic (username + password). The card exposes all three; the connector picks the
 * first configured in that order. Mask semantics match MISP / webhooks: "••••••••" on
 * reload, cleared on focus so typing REPLACES the stored secret.
 */
export function TaxiiServersCard() {
  const { data, error, isLoading } = useTaxiiServers()
  const save = useSaveTaxiiServers()
  const test = useTestTaxiiServer()
  const [rows, setRows] = useState<TaxiiServer[]>([])
  const [testResults, setTestResults] = useState<Record<number, SourceTestResult>>({})

  useEffect(() => {
    if (data) setRows(data.servers.map((s) => ({ ...s })))
  }, [data])

  if (isLoading) return <Loading />
  if (error || !data) return <ErrorCard error={error} />

  const update = (index: number, patch: Partial<TaxiiServer>) => {
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
    const cleaned = rows.map((row) => ({
      ...row,
      name: row.name.trim(),
      url: row.url.trim(),
      collection: row.collection.trim(),
      env_api_key: row.env_api_key.trim(),
      username: row.username.trim(),
    }))
    save.mutate(cleaned)
  }

  const onTest = async (index: number) => {
    const result = await test.mutateAsync(rows[index]).catch((err: Error) => ({ ok: false, error: err.message }))
    setTestResults((prev) => ({ ...prev, [index]: result }))
  }

  return (
    <Card
      title="TAXII 2.1 servers"
      actions={
        <div className="flex gap-2">
          <button type="button" className="btn btn-ghost btn-sm" onClick={addRow}>Add server</button>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={save.isPending}
            onClick={onSave}
          >
            {save.isPending ? 'Saving…' : 'Save TAXII servers'}
          </button>
        </div>
      }
    >
      <p className="text-xs text-gray-400 mb-4">
        Argus subscribes to each configured TAXII 2.1 server and pulls STIX{' '}
        <code className="mono">report</code> objects that mention the target.
        Auth precedence per server: env var → <code className="mono">api_key</code> toml →{' '}
        username + password (HTTP Basic) → anonymous.
      </p>
      {save.error && <p className="text-sm text-red-400 mb-3" role="alert">{save.error.message}</p>}
      {rows.length === 0 ? (
        <p className="text-sm text-gray-400">No TAXII servers configured.</p>
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
  row: TaxiiServer
  testing: boolean
  result: SourceTestResult | undefined
  onChange: (patch: Partial<TaxiiServer>) => void
  onRemove: () => void
  onTest: () => void
}) {
  return (
    <div className="border border-gray-700 rounded p-3 bg-gray-800/50">
      <div className="grid grid-cols-2 gap-3">
        <label className="block">
          <span className="text-xs text-gray-400">Name (publisher: <code className="mono">TAXII:&lt;name&gt;</code>)</span>
          <input
            type="text"
            className="input w-full"
            value={row.name}
            onChange={(e) => onChange({ name: e.target.value })}
            placeholder="ESET APT Reports"
          />
        </label>
        <label className="block">
          <span className="text-xs text-gray-400">API Root URL</span>
          <input
            type="url"
            className="input w-full"
            value={row.url}
            onChange={(e) => onChange({ url: e.target.value })}
            placeholder="https://taxii.example.com/taxii2/api1"
          />
        </label>
        <label className="block">
          <span className="text-xs text-gray-400">Collection id or alias</span>
          <input
            type="text"
            className="input w-full"
            value={row.collection}
            onChange={(e) => onChange({ collection: e.target.value })}
            placeholder="apt-reports"
          />
        </label>
        <label className="block">
          <span className="text-xs text-gray-400">Window (days, blank = unlimited)</span>
          <input
            type="number"
            min={1}
            className="input w-full"
            value={row.added_after_days ?? ''}
            onChange={(e) => onChange({ added_after_days: e.target.value === '' ? null : Number(e.target.value) })}
          />
        </label>
        <label className="block col-span-2">
          <span className="text-xs text-gray-400">Env var for Bearer token (preferred over api_key)</span>
          <input
            type="text"
            className="input w-full"
            value={row.env_api_key}
            onChange={(e) => onChange({ env_api_key: e.target.value })}
            placeholder="ESET_TAXII_TOKEN"
          />
        </label>
        <label className="block">
          <span className="text-xs text-gray-400">Bearer token (fallback — leave masked to keep)</span>
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
        <div />
        <label className="block">
          <span className="text-xs text-gray-400">HTTP Basic username (alternative)</span>
          <input
            type="text"
            className="input w-full"
            value={row.username}
            onChange={(e) => onChange({ username: e.target.value })}
            placeholder="argus-reader"
            autoComplete="username"
          />
        </label>
        <label className="block">
          <span className="text-xs text-gray-400">HTTP Basic password (leave masked to keep)</span>
          <input
            type="password"
            className="input w-full"
            value={row.password}
            onFocus={(e) => { if (e.target.value === MASK_VALUE) onChange({ password: '' }) }}
            onChange={(e) => onChange({ password: e.target.value })}
            placeholder="(none)"
            autoComplete="new-password"
          />
        </label>
        <label className="flex items-center gap-2 self-end pb-1 col-span-2">
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
          disabled={testing || !row.url.trim() || !row.collection.trim()}
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
              ? `OK — ${result.objects_sampled ?? 0} object(s) sampled`
              : `Failed: ${result.error ?? 'unknown error'}`}
          </span>
        )}
      </div>
    </div>
  )
}
