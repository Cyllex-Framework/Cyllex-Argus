import { useEffect, useState } from 'react'
import { useEnrichers, useToggleEnricher } from '../../api/hooks'
import type { Enricher } from '../../api/types'
import { Card } from '../../components/Card'
import { ErrorCard, Loading } from '../../components/QueryState'

const MASK_VALUE = '••••••••'

/**
 * Opt-in table of built-in enrichers. Every row shows the enricher's `outbound` sentence
 * — exactly what leaves the machine when it runs — so the operator sees the OPSEC trade-off
 * BEFORE flipping the toggle. The default state of a fresh install is: every row disabled.
 *
 * Key-gated enrichers (VirusTotal) expand to show an API-key input + env-var hint when
 * enabled. Masked key values preserve the stored key — the operator doesn't have to
 * re-paste it to toggle `enabled` off and on.
 */
export function EnrichersCard() {
  const { data, error, isLoading } = useEnrichers()
  const toggle = useToggleEnricher()
  if (isLoading) return <Loading />
  if (error || !data) return <ErrorCard error={error} />
  return (
    <Card title="Enrichment (opt-in)">
      <p className="text-xs text-gray-400 mb-4">
        Argus is receive-only by default. Enable a specific enricher below only when you accept
        that the described outbound traffic will leave your machine. The chosen enricher fires
        automatically on validated IOCs and CVEs during an investigation.
      </p>
      {toggle.error && <p className="text-sm text-red-400 mb-3" role="alert">{toggle.error.message}</p>}
      <table className="data-table w-full">
        <thead>
          <tr>
            <th>Enricher</th>
            <th>Accepts</th>
            <th>Outbound</th>
            <th>Enabled</th>
          </tr>
        </thead>
        <tbody>
          {data.enrichers.map((enricher) => (
            <EnricherRow
              key={enricher.name}
              enricher={enricher}
              disabled={toggle.isPending}
              onSave={(vars) => toggle.mutate(vars)}
            />
          ))}
        </tbody>
      </table>
    </Card>
  )
}


function EnricherRow({
  enricher, disabled, onSave,
}: {
  enricher: Enricher
  disabled: boolean
  onSave: (vars: { name: string; enabled: boolean; api_key?: string; env_api_key?: string }) => void
}) {
  const [apiKey, setApiKey] = useState(enricher.api_key)
  const [envApiKey, setEnvApiKey] = useState(enricher.env_api_key)
  // Keep local state aligned with the server round-trip (so a save of ON clears to the mask).
  useEffect(() => { setApiKey(enricher.api_key) }, [enricher.api_key])
  useEffect(() => { setEnvApiKey(enricher.env_api_key) }, [enricher.env_api_key])

  const saveToggle = (enabled: boolean) => {
    if (!enricher.requires_api_key) {
      onSave({ name: enricher.name, enabled })
      return
    }
    // Mask → let the server keep the stored key. Otherwise send the plaintext (or the empty string to clear).
    onSave({
      name: enricher.name, enabled,
      api_key: apiKey, env_api_key: envApiKey,
    })
  }

  const saveKeyFields = () => {
    onSave({
      name: enricher.name, enabled: enricher.enabled,
      api_key: apiKey, env_api_key: envApiKey,
    })
  }

  return (
    <>
      <tr>
        <td>
          <div className="font-semibold">{enricher.name}</div>
          <div className="text-xs text-gray-400">{enricher.description}</div>
        </td>
        <td className="text-xs text-gray-300">{enricher.supported_types.join(', ')}</td>
        <td className="text-xs text-yellow-300 max-w-md">{enricher.outbound}</td>
        <td>
          <label className="inline-flex items-center gap-2">
            <input
              type="checkbox"
              aria-label={`Enable ${enricher.name}`}
              checked={enricher.enabled}
              disabled={disabled}
              onChange={(event) => saveToggle(event.target.checked)}
            />
            <span className={enricher.enabled ? 'text-emerald-400' : 'text-gray-400'}>
              {enricher.enabled ? 'ON' : 'OFF'}
            </span>
          </label>
        </td>
      </tr>
      {enricher.requires_api_key && enricher.enabled && (
        <tr className="bg-gray-800/40">
          <td colSpan={4} className="p-3">
            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <span className="text-xs text-gray-400">API key (leave masked to keep stored)</span>
                <input
                  type="password"
                  className="input w-full"
                  value={apiKey}
                  onFocus={(e) => { if (e.target.value === MASK_VALUE) setApiKey('') }}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder={enricher.api_key_configured ? MASK_VALUE : '(none — set env var or paste a key)'}
                  autoComplete="new-password"
                />
              </label>
              <label className="block">
                <span className="text-xs text-gray-400">
                  Env var for key (preferred — key never touches disk)
                </span>
                <input
                  type="text"
                  className="input w-full"
                  value={envApiKey}
                  onChange={(e) => setEnvApiKey(e.target.value)}
                  placeholder="VIRUSTOTAL_API_KEY"
                />
              </label>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <button
                type="button"
                className="btn btn-primary btn-sm"
                disabled={disabled}
                onClick={saveKeyFields}
              >
                Save key
              </button>
              {!enricher.api_key_configured && !envApiKey.trim() && (
                <span className="text-xs text-yellow-400">
                  No key configured — this enricher will error out on every call.
                </span>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}
