import { useState } from 'react'
import { useEnrichers, useInvokeEnricher } from '../../api/hooks'
import type { EnrichmentResult, StixObservableType } from '../../api/types'
import { Card } from '../../components/Card'

const TYPES: readonly { value: StixObservableType; label: string }[] = [
  { value: 'domain-name', label: 'domain-name' },
  { value: 'ipv4-addr', label: 'ipv4-addr' },
  { value: 'ipv6-addr', label: 'ipv6-addr' },
  { value: 'url', label: 'url' },
  { value: 'file-hash', label: 'file-hash' },
  { value: 'vulnerability', label: 'vulnerability (CVE)' },
] as const

/** Standalone enrich panel: pick an enricher that's enabled, type an indicator, see the
 * findings. The automatic path during an investigation fires the same enricher behind the
 * scenes; this is the manual escape hatch for one-off lookups from the UI. */
export function EnrichCard() {
  const { data: catalog } = useEnrichers()
  const invoke = useInvokeEnricher()
  const [indicator, setIndicator] = useState('')
  const [indicatorType, setIndicatorType] = useState<StixObservableType>('domain-name')
  const [enricher, setEnricher] = useState('')
  const [result, setResult] = useState<EnrichmentResult | null>(null)

  const enabled = (catalog?.enrichers ?? []).filter((e) => e.enabled)
  const compatible = enabled.filter((e) => e.supported_types.includes(indicatorType))

  const run = () => {
    if (!indicator.trim() || !enricher) return
    setResult(null)
    invoke.mutate(
      { name: enricher, indicator: indicator.trim(), indicator_type: indicatorType },
      { onSuccess: setResult },
    )
  }

  return (
    <Card title="Enrich an indicator">
      <p className="text-xs text-gray-400 mb-3">
        Standalone enrichment for one indicator. Only enrichers you have enabled in Settings
        appear here — enable one first.
      </p>
      {enabled.length === 0 ? (
        <p className="text-sm text-yellow-400">
          No enricher is enabled. Visit the Settings page to opt into one.
        </p>
      ) : (
        <div className="flex flex-col gap-2">
          <div className="flex gap-2 items-end">
            <label className="text-xs text-gray-400 flex flex-col flex-1">
              Indicator
              <input className="input" value={indicator} onChange={(e) => setIndicator(e.target.value)}
                placeholder="example.com, 1.2.3.4, CVE-2024-12345, SHA256…" />
            </label>
            <label className="text-xs text-gray-400 flex flex-col">
              Type
              <select className="select" value={indicatorType}
                onChange={(e) => setIndicatorType(e.target.value as StixObservableType)}>
                {TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </label>
          </div>
          <label className="text-xs text-gray-400 flex flex-col">
            Enricher
            <select className="select" value={enricher} onChange={(e) => setEnricher(e.target.value)}>
              <option value="">(select one)</option>
              {compatible.map((e) => <option key={e.name} value={e.name}>{e.name}</option>)}
            </select>
          </label>
          <button type="button" className="btn btn-primary btn-sm w-fit"
            disabled={invoke.isPending || !indicator.trim() || !enricher} onClick={run}>
            {invoke.isPending ? 'Running…' : 'Enrich'}
          </button>
          {invoke.error && <p className="text-sm text-red-400" role="alert">{invoke.error.message}</p>}
          {result && (
            <div className="mt-3 text-sm">
              {result.error ? (
                <p className="text-yellow-400" role="status">Error: {result.error}</p>
              ) : result.findings.length === 0 ? (
                <p className="text-gray-400">No findings in {result.duration_ms} ms.</p>
              ) : (
                <>
                  <p className="text-xs text-gray-400 mb-1">
                    {result.findings.length} finding(s) in {result.duration_ms} ms:
                  </p>
                  <table className="data-table w-full text-xs">
                    <thead><tr><th>Key</th><th>Value</th><th>Observed</th><th>Detail</th></tr></thead>
                    <tbody>
                      {result.findings.map((f, i) => (
                        <tr key={i}>
                          <td className="text-gray-400">{f.key}</td>
                          <td>{f.value}</td>
                          <td className="text-gray-400">{f.observed_at ?? '-'}</td>
                          <td className="text-gray-400">{f.detail ?? '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </Card>
  )
}
