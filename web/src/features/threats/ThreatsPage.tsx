import { useDeferredValue, useState } from 'react'
import { Link } from 'react-router-dom'
import { useThreats } from '../../api/hooks'
import { Card } from '../../components/Card'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'

const TYPES = ['', 'intrusion-set', 'campaign', 'malware', 'tool', 'attack-pattern', 'vulnerability', 'identity', 'location', 'indicator']

export function ThreatsPage() {
  const [q, setQ] = useState('')
  const [type, setType] = useState('')
  const [catalog, setCatalog] = useState(false)
  const deferredQ = useDeferredValue(q)
  const { data, error, isLoading, isPlaceholderData } = useThreats({ q: deferredQ.trim(), type, catalog })
  return (
    <Card title="Threats">
      <div className="flex gap-3 mb-4 items-center">
        <input className="input flex-1" placeholder="Search by name or alias (e.g. Octo Tempest)" aria-label="Search threats"
          value={q} onChange={(event) => setQ(event.target.value)} />
        <select className="select" aria-label="Filter by type" value={type} onChange={(event) => setType(event.target.value)}>
          {TYPES.map((t) => <option key={t} value={t}>{t || 'All types'}</option>)}
        </select>
        <label className="flex items-center gap-2 text-sm text-gray-400 whitespace-nowrap">
          <input type="checkbox" checked={catalog} onChange={(event) => setCatalog(event.target.checked)} />
          Include ATT&CK catalog
        </label>
      </div>
      {isLoading ? <Loading /> : error || !data ? <ErrorCard error={error} /> : (
        <div aria-busy={isPlaceholderData} className={isPlaceholderData ? 'opacity-60' : undefined}>
          {data.length === 0 ? (
            <EmptyState>No threats with facts yet. Run an investigation, or include the ATT&CK catalog.</EmptyState>
          ) : (
            <table className="data-table w-full">
              <thead><tr><th>Name</th><th>Type</th><th>Facts</th><th>Source</th></tr></thead>
              <tbody>
                {data.map((threat) => (
                  <tr key={threat.id}>
                    <td><Link to={`/threats/${encodeURIComponent(threat.id)}`} className="text-purple-400 hover:underline">{threat.label}</Link></td>
                    <td className="text-gray-400">{threat.stix_type}</td>
                    <td>{threat.facts}</td>
                    <td className="text-xs text-gray-400">{threat.attack ? 'MITRE ATT&CK' : 'Learned from sources'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </Card>
  )
}
