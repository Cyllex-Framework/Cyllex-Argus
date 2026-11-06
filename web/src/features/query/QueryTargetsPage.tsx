import { useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQueryTargets } from '../../api/hooks'
import { Card } from '../../components/Card'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'

// Common sector labels — same conservative list the Health detector and Validator share.
// Pre-populates the datalist so the operator doesn't have to remember exact spellings.
const SECTOR_SUGGESTIONS = [
  'aerospace', 'aerospace and defense', 'automotive', 'aviation', 'bpo',
  'business process outsourcing (bpo)', 'cloud identity providers',
  'energy', 'financial services', 'financial-services', 'healthcare',
  'information technology', 'insurance', 'it help desks',
  'it managed service providers', 'logistics', 'manufacturing',
  'pharmaceuticals', 'retail', 'telecommunications',
]

// Common ISO 3166 alpha-2 codes to prefill. Not exhaustive — the input stays free-text.
const COUNTRY_SUGGESTIONS = [
  'US', 'GB', 'FR', 'DE', 'ES', 'IT', 'NL', 'PT', 'BE', 'CA', 'MX', 'BR',
  'JP', 'KR', 'SG', 'AU', 'NZ', 'IL', 'TR', 'SA', 'AE', 'UA', 'IR', 'RU',
]

type Row = NonNullable<ReturnType<typeof useQueryTargets>['data']>['actors'][number]

/** Query page for the CTI question "who targets this sector / country?".
 *
 * Two merged paths behind the single row list:
 * - Direct: actors whose own `attributes.sectors[]` includes the sector (0.13+ shape).
 * - Indirect: actors with `targets` claims against identity entities whose
 *   `attributes.sector` matches (pre-0.13).
 *
 * Each row carries a source chip so the operator knows which path it came from; direct
 * hits sort above indirect, matching the server's ranking.
 */
export function QueryTargetsPage() {
  const [sector, setSector] = useState('')
  const [country, setCountry] = useState('')
  const [applied, setApplied] = useState<{ sector: string; country: string } | null>(null)
  const { data, error, isLoading } = useQueryTargets(applied?.sector ?? '', applied?.country ?? '')
  const formRef = useRef<HTMLFormElement | null>(null)

  const run = () => {
    if (!sector.trim() && !country.trim()) return
    setApplied({ sector: sector.trim(), country: country.trim() })
  }

  const totals = useMemo(() => {
    if (!data) return null
    const direct = (data.matched_by_sectors_attribute ?? 0)
    const indirect = data.matched_identities
    return { direct, indirect }
  }, [data])

  return (
    <Card title="Query: actors targeting a sector or country">
      <p className="text-xs text-gray-400 mb-3">
        Returns actors whose own <code className="mono">attributes.sectors[]</code> matches
        the sector (direct), plus actors with observed <code className="mono">targets</code>
        assessments against identity entities whose attributes match (indirect). Direct hits
        rank first — the attribution is on the actor itself, not a possibly-stale identity
        relationship.
      </p>
      <form ref={formRef} onSubmit={(e) => { e.preventDefault(); run() }} className="flex flex-wrap gap-3 items-end mb-4">
        <label className="text-xs text-gray-400 flex flex-col flex-1 min-w-48">
          Sector
          <input className="input" list="sector-suggestions"
            value={sector} onChange={(e) => setSector(e.target.value)}
            placeholder="start typing: healthcare, retail, …" />
          <datalist id="sector-suggestions">
            {SECTOR_SUGGESTIONS.map((s) => <option key={s} value={s} />)}
          </datalist>
        </label>
        <label className="text-xs text-gray-400 flex flex-col w-40">
          Country (ISO alpha-2)
          <input className="input" list="country-suggestions"
            value={country} onChange={(e) => setCountry(e.target.value)}
            placeholder="US, GB, DE…" />
          <datalist id="country-suggestions">
            {COUNTRY_SUGGESTIONS.map((c) => <option key={c} value={c} />)}
          </datalist>
        </label>
        <button type="submit" className="btn btn-primary btn-sm">Run</button>
      </form>

      {!applied && <EmptyState>Enter a sector and/or a country, then press Run.</EmptyState>}
      {applied && isLoading && <Loading />}
      {applied && error && <ErrorCard error={error} />}
      {applied && data && (
        <>
          <div className="text-xs text-gray-400 mb-3 flex flex-wrap gap-x-6 gap-y-1">
            {totals && totals.direct > 0 && (
              <span><strong className="text-emerald-300">{totals.direct}</strong> actor(s) via <code className="mono">attributes.sectors</code></span>
            )}
            <span><strong className="text-gray-300">{totals?.indirect ?? 0}</strong> identity entity(ies) matched</span>
            <span><strong className="text-gray-300">{data.actors.length}</strong> row(s) total</span>
          </div>
          {data.actors.length === 0 ? (
            <EmptyState>No actors matched. Tag more identity entities, or run an investigation that captures the sector.</EmptyState>
          ) : (
            <table className="data-table w-full">
              <thead><tr><th>Actor</th><th>Type</th><th>Source</th><th>Assessments</th></tr></thead>
              <tbody>
                {data.actors.map((row: Row) => (
                  <tr key={row.entity_id}>
                    <td>
                      <Link to={`/threats/${encodeURIComponent(row.entity_id)}`} className="text-blue-400 hover:underline">
                        {row.canonical_name}
                      </Link>
                    </td>
                    <td className="text-gray-400">{row.stix_type}</td>
                    <td><SourceChip source={row.source} /></td>
                    <td>{row.assessment_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </Card>
  )
}

function SourceChip({ source }: { source: Row['source'] }) {
  if (source === 'sectors') {
    return (
      <span className="mono text-xs px-1.5 py-0.5 rounded bg-emerald-900/40 text-emerald-200 border border-emerald-700/40"
        title="Direct attribution: the actor has this sector in its attributes.sectors[] list.">
        direct
      </span>
    )
  }
  if (source === 'targets-identity') {
    return (
      <span className="mono text-xs px-1.5 py-0.5 rounded bg-sky-900/40 text-sky-200 border border-sky-700/40"
        title="Indirect: the actor has a `targets` assessment against an identity whose attributes match.">
        via identity
      </span>
    )
  }
  return <span className="text-xs text-gray-500">—</span>
}
