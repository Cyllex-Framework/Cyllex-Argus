import { Link } from 'react-router-dom'
import { useOverview } from '../../api/hooks'
import { Card } from '../../components/Card'
import { PIPELINE_NEEDS, SetupNotice } from '../../components/SetupNotice'
import { StatTile } from '../../components/StatTile'
import { JobStatePill } from '../../components/badges'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'
import { formatDateTime } from '../../lib/format'
import { HealthCard } from './HealthCard'

/**
 * A fresh install is guided from the first screen: what is missing, and its fix, above
 * everything else. Then the knowledge base and the recent work — and housekeeping last.
 *
 * Data health was briefly moved above the overview on the theory that "what needs a decision"
 * should outrank "what the totals are". On a real store that opened the app on four columns of
 * failed-document URLs and untagged identities: a debug console, not a dashboard. The card now
 * collapses to a single line of counts, and it sits back under the overview.
 */
export function DashboardPage() {
  return (
    <div className="space-y-6">
      <SetupNotice needs={PIPELINE_NEEDS} purpose="investigate threats or ingest documents" />
      <Overview />
      <HealthCard />
    </div>
  )
}

function Overview() {
  const { data, error, isLoading } = useOverview()
  if (isLoading) return <Loading />
  if (error || !data) return <ErrorCard error={error} />
  const { counts } = data
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-5 gap-4">
        <StatTile label="Threats with facts" value={counts.threats} tone="text-purple-400" />
        <StatTile label="Validated documents" value={counts.documents.validated ?? 0} tone="text-sky-400" />
        <StatTile label="Corroborated facts" value={counts.assessments.corroborated ?? 0} tone="text-emerald-400" />
        <StatTile label="Contested facts" value={counts.assessments.contested ?? 0} tone="text-red-400" />
        <StatTile label="Investigations" value={counts.investigations} />
      </div>
      <div className="grid grid-cols-3 gap-6">
        <Card title="Recent investigations" className="col-span-2">
          {data.recent_investigations.length === 0 ? (
            <EmptyState>No investigations yet. Start one from the Investigations tab.</EmptyState>
          ) : (
            <table className="data-table w-full">
              <thead><tr><th>Target</th><th>State</th><th>Documents</th><th>Started</th></tr></thead>
              <tbody>
                {data.recent_investigations.map((inv) => (
                  <tr key={inv.id}>
                    <td><Link to={`/investigations/${inv.id}/dashboard`} className="text-purple-400 hover:underline">{inv.target}</Link></td>
                    <td><JobStatePill state={inv.state} /></td>
                    <td className="text-xs text-gray-400">{Object.entries(inv.stage_counts).map(([s, n]) => `${s}: ${n}`).join(' · ')}</td>
                    <td className="text-xs text-gray-400">{formatDateTime(inv.started_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card title="Sources to rate">
          {data.unrated_publishers.length === 0 ? (
            <EmptyState>Every source has a reliability rating.</EmptyState>
          ) : (
            <>
              <p className="text-xs text-gray-400 mb-3">
                These publishers are still rated F (cannot be judged), so their facts carry low confidence.
              </p>
              <ul className="space-y-1">
                {data.unrated_publishers.map((p) => (
                  <li key={p.id}><Link to="/sources" className="text-purple-400 hover:underline text-sm">{p.name}</Link></li>
                ))}
              </ul>
            </>
          )}
        </Card>
      </div>
    </div>
  )
}
