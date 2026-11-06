import { useEffect, useState } from 'react'
import { useSaveWebhooks, useTestWebhook, useWebhooks } from '../../api/hooks'
import type { SourceTestResult, Webhook } from '../../api/types'
import { Card } from '../../components/Card'
import { ErrorCard, Loading } from '../../components/QueryState'

const MASK_VALUE = '••••••••'

function emptyWebhook(): Webhook {
  return { url: '', secret: '', env_secret: '', on_states: [], enabled: true }
}

/**
 * UI for the `[[webhook]]` list in argus.toml.
 *
 * Argus fires each enabled webhook when an investigation reaches a terminal state
 * (FINISHED / PAUSED). The row's "Test" button fires a one-shot synthetic FINISHED
 * payload — useful to confirm the Slack / Discord / Teams integration before an
 * investigation actually completes.
 *
 * Signed webhooks: when a secret is configured, every POST carries an
 * `X-Argus-Signature: sha256=<hex>` header (HMAC-SHA256 over
 * `timestamp + "." + body`). Standard enough to drop into a Stripe / GitHub-style verifier.
 */
export function WebhooksCard() {
  const { data, error, isLoading } = useWebhooks()
  const save = useSaveWebhooks()
  const test = useTestWebhook()
  const [rows, setRows] = useState<Webhook[]>([])
  const [testResults, setTestResults] = useState<Record<number, SourceTestResult>>({})

  useEffect(() => {
    if (data) setRows(data.webhooks.map((hook) => ({ ...hook, on_states: [...hook.on_states] })))
  }, [data])

  if (isLoading) return <Loading />
  if (error || !data) return <ErrorCard error={error} />

  const update = (index: number, patch: Partial<Webhook>) => {
    setRows((prev) => prev.map((row, i) => (i === index ? { ...row, ...patch } : row)))
  }

  const toggleState = (index: number, state: 'finished' | 'paused', on: boolean) => {
    setRows((prev) => prev.map((row, i) => {
      if (i !== index) return row
      const current = new Set(row.on_states)
      if (on) current.add(state); else current.delete(state)
      return { ...row, on_states: Array.from(current) }
    }))
  }

  const addRow = () => setRows((prev) => [...prev, emptyWebhook()])
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
      ...row, url: row.url.trim(), env_secret: row.env_secret.trim(),
    }))
    save.mutate(cleaned)
  }

  const onTest = async (index: number) => {
    const result = await test.mutateAsync(rows[index]).catch((err: Error) => ({ ok: false, error: err.message }))
    setTestResults((prev) => ({ ...prev, [index]: result }))
  }

  return (
    <Card
      title="Outbound webhooks"
      actions={
        <div className="flex gap-2">
          <button type="button" className="btn btn-ghost btn-sm" onClick={addRow}>Add webhook</button>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={save.isPending}
            onClick={onSave}
          >
            {save.isPending ? 'Saving…' : 'Save webhooks'}
          </button>
        </div>
      }
    >
      <p className="text-xs text-gray-400 mb-4">
        Each webhook receives a signed JSON payload the moment an investigation finishes or
        pauses. Secret-less webhooks are posted unsigned (useful for internal routers on a
        trusted LAN). When a secret is configured, every POST carries{' '}
        <code className="mono">X-Argus-Signature: sha256=…</code> for verification.
      </p>
      {save.error && <p className="text-sm text-red-400 mb-3" role="alert">{save.error.message}</p>}
      {rows.length === 0 ? (
        <p className="text-sm text-gray-400">No webhooks configured.</p>
      ) : (
        <div className="space-y-5">
          {rows.map((row, index) => (
            <WebhookRow
              key={index}
              row={row}
              testing={test.isPending}
              result={testResults[index]}
              onChange={(patch) => update(index, patch)}
              onToggleState={(state, on) => toggleState(index, state, on)}
              onRemove={() => removeRow(index)}
              onTest={() => onTest(index)}
            />
          ))}
        </div>
      )}
    </Card>
  )
}


function WebhookRow({
  row, testing, result, onChange, onToggleState, onRemove, onTest,
}: {
  row: Webhook
  testing: boolean
  result: SourceTestResult | undefined
  onChange: (patch: Partial<Webhook>) => void
  onToggleState: (state: 'finished' | 'paused', on: boolean) => void
  onRemove: () => void
  onTest: () => void
}) {
  const firesOnFinished = row.on_states.length === 0 || row.on_states.includes('finished')
  const firesOnPaused = row.on_states.length === 0 || row.on_states.includes('paused')
  return (
    <div className="border border-gray-700 rounded p-3 bg-gray-800/50">
      <div className="space-y-3">
        <label className="block">
          <span className="text-xs text-gray-400">URL</span>
          <input
            type="url"
            className="input w-full"
            value={row.url}
            onChange={(e) => onChange({ url: e.target.value })}
            placeholder="https://hooks.slack.com/services/..."
          />
        </label>
        <div className="grid grid-cols-2 gap-3">
          <label className="block">
            <span className="text-xs text-gray-400">HMAC secret (leave masked to keep)</span>
            <input
              type="password"
              className="input w-full"
              value={row.secret}
              onFocus={(e) => { if (e.target.value === MASK_VALUE) onChange({ secret: '' }) }}
              onChange={(e) => onChange({ secret: e.target.value })}
              placeholder="(none — payload will be unsigned)"
              autoComplete="new-password"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Env var for secret (preferred)</span>
            <input
              type="text"
              className="input w-full"
              value={row.env_secret}
              onChange={(e) => onChange({ env_secret: e.target.value })}
              placeholder="ARGUS_HOOK_SECRET"
            />
          </label>
        </div>
        <div>
          <span className="text-xs text-gray-400 block mb-1">Fire on</span>
          <div className="flex gap-4">
            <label className="inline-flex items-center gap-2">
              <input
                type="checkbox"
                checked={firesOnFinished}
                onChange={(e) => onToggleState('finished', e.target.checked)}
              />
              <span>finished</span>
            </label>
            <label className="inline-flex items-center gap-2">
              <input
                type="checkbox"
                checked={firesOnPaused}
                onChange={(e) => onToggleState('paused', e.target.checked)}
              />
              <span>paused</span>
            </label>
            <span className="text-xs text-gray-500 self-center">
              (both unchecked = fire on both; this matches the "no filter" default)
            </span>
          </div>
        </div>
        <label className="inline-flex items-center gap-2">
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
          Send test payload
        </button>
        <button type="button" className="btn btn-ghost btn-sm text-red-400" onClick={onRemove}>
          Remove
        </button>
        {result && (
          <span className={`text-xs ${result.ok ? 'text-emerald-400' : 'text-red-400'}`}>
            {result.ok
              ? `Delivered (${result.detail ?? 'ok'})`
              : `Failed: ${result.error ?? result.detail ?? 'unknown error'}`}
          </span>
        )}
      </div>
    </div>
  )
}
