/**
 * `/threats/<id>/history` — diff view that answers "what changed about this threat since <date>".
 *
 * Three buckets, backed by `GET /api/threats/<id>/history?since=<iso>`:
 *
 * - **Investigations** since the picker date — a timeline-ish list, with start/finish/state so an
 *   operator can see which runs produced the delta they are looking at.
 * - **New assessments** — triples (subject, predicate, object) that didn't exist before the
 *   picker date. "The actor now has a `uses` claim against T1087.002 that it didn't before."
 * - **Touched assessments** — triples that existed before, but got updated after. Where "a new
 *   corroborating source arrived" surfaces today, without needing a status-history table.
 *
 * Default `since` is the start of the second-most-recent investigation for this entity, so
 * opening the page shows "what the latest run added over the previous one" — the question CTI
 * analysts actually want answered when they re-investigate a known actor.
 */

import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useThreat, useThreatHistory, type ThreatHistoryAssessment } from '../../api/hooks'
import { Card } from '../../components/Card'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'

export function ThreatHistoryPage() {
  const { id = '' } = useParams()
  const threat = useThreat(id)
  // null = "use server default" (second-most-recent run or epoch). The input is a plain `date` for
  // operator friendliness; we send it to the server as midnight-UTC that day.
  const [sinceDate, setSinceDate] = useState<string>('')
  const since = sinceDate ? `${sinceDate}T00:00:00Z` : null
  const history = useThreatHistory(id || null, since)

  if (threat.isLoading) return <Loading />
  if (threat.error || !threat.data) return <ErrorCard error={threat.error} />

  const entity = threat.data.entity

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <nav aria-label="Breadcrumb" className="text-sm text-gray-400 mb-1">
            <Link to={`/threats/${encodeURIComponent(id)}`} className="hover:text-white">{entity.name}</Link>
            {' · '}<span className="text-gray-200">history</span>
          </nav>
          <h1 className="text-2xl font-semibold break-words">What changed about {entity.name}</h1>
          <p className="text-sm text-gray-400">
            Compares the current knowledge against a point in time. Defaults to the start of the
            previous investigation for this threat.
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm text-gray-300">
          Since
          <input
            type="date"
            className="input"
            value={sinceDate}
            onChange={(event) => setSinceDate(event.target.value)}
            aria-label="Show changes since (date)"
          />
          {sinceDate && (
            <button type="button" className="text-xs text-gray-400 hover:text-white"
              onClick={() => setSinceDate('')}>Clear</button>
          )}
        </label>
      </div>

      {history.isLoading && <Loading />}
      {history.error && <ErrorCard error={history.error} />}
      {history.data && <HistoryBody id={id} history={history.data} />}
    </div>
  )
}

function HistoryBody({ id, history }: {
  id: string
  history: NonNullable<ReturnType<typeof useThreatHistory>['data']>
}) {
  const investigations = history.investigations
  const sinceLabel = useMemo(() => {
    try { return new Date(history.since).toLocaleString() } catch { return history.since }
  }, [history.since])
  const nothing =
    investigations.length === 0 &&
    history.new_assessments.length === 0 &&
    history.touched_assessments.length === 0 &&
    history.new_aliases.length === 0

  if (nothing) {
    return (
      <Card>
        <EmptyState>
          Nothing new since {sinceLabel}. Re-investigate this threat or move the "Since" date back
          to see earlier changes.
        </EmptyState>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      <p className="text-xs text-gray-500">Changes since <span className="font-mono">{sinceLabel}</span></p>

      <Card title={`Investigations since (${investigations.length})`}>
        {investigations.length === 0 ? (
          <EmptyState>No investigations in that window.</EmptyState>
        ) : (
          <ul className="divide-y divide-gray-700">
            {investigations.map((inv) => (
              <li key={inv.id} className="py-2 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <Link to={`/investigations/${inv.id}/dashboard`}
                    className="text-sm text-purple-400 hover:underline truncate">
                    {inv.target}
                  </Link>
                  <div className="text-xs text-gray-500">
                    started {new Date(inv.started_at).toLocaleString()}
                    {inv.finished_at ? ` · finished ${new Date(inv.finished_at).toLocaleString()}` : ' · in progress'}
                  </div>
                </div>
                <span className="text-xs text-gray-400 flex-shrink-0">{inv.state}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <AssessmentListCard
        title="New assessments"
        description="Subject-predicate-object triples that did not exist before the picker date."
        items={history.new_assessments}
        entityId={id}
      />
      <AssessmentListCard
        title="Touched assessments"
        description="Triples that existed before but got updated after — a new corroborating source likely arrived."
        items={history.touched_assessments}
        entityId={id}
      />

      <Card title={`New aliases (${history.new_aliases.length})`}>
        {history.new_aliases.length === 0 ? (
          <EmptyState>No new document-learned aliases.</EmptyState>
        ) : (
          <ul className="flex flex-wrap gap-2">
            {history.new_aliases.map((al, i) => (
              <li key={`${al.alias}-${i}`} className="px-2 py-0.5 rounded text-xs bg-yellow-900/40 text-yellow-200 border border-yellow-700/40">
                {al.alias}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}

function AssessmentListCard({ title, description, items, entityId }: {
  title: string; description: string; items: ThreatHistoryAssessment[]; entityId: string
}) {
  return (
    <Card title={`${title} (${items.length})`}>
      <p className="text-xs text-gray-500 mb-3">{description}</p>
      {items.length === 0 ? (
        <EmptyState>Nothing in this bucket.</EmptyState>
      ) : (
        <ul className="divide-y divide-gray-700">
          {items.map((a) => (
            <li key={a.id} className="py-2 flex items-center justify-between gap-3">
              <div className="min-w-0 flex items-center gap-2 flex-wrap">
                <span className="text-xs text-gray-400 font-mono">{a.predicate}</span>
                <span className="text-sm text-gray-200">
                  {a.subject_entity_id === entityId ? '→' : '←'}{' '}
                  <Link to={`/threats/${encodeURIComponent(a.subject_entity_id === entityId ? a.object_entity_id : a.subject_entity_id)}`}
                    className="text-purple-400 hover:underline break-all">
                    {a.subject_entity_id === entityId ? a.object_entity_id : a.subject_entity_id}
                  </Link>
                </span>
                <span className={`text-xs px-1.5 py-0.5 rounded ${statusTone(a.status)}`}>{a.status}</span>
                {a.admiralty && <span className="text-xs text-gray-500">({a.admiralty})</span>}
              </div>
              <span className="text-xs text-gray-500 flex-shrink-0">conf {a.confidence}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

function statusTone(status: string): string {
  if (status === 'corroborated') return 'bg-emerald-900/40 text-emerald-200 border border-emerald-700/40'
  if (status === 'contested') return 'bg-red-900/40 text-red-200 border border-red-700/40'
  return 'bg-gray-800 text-gray-300 border border-gray-700'
}
