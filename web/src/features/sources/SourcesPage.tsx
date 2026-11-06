import { useSetSourceTlp, useSources, useUpdateSource } from '../../api/hooks'
import type { Tlp } from '../../api/types'
import { Card } from '../../components/Card'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'
import { DuplicateSourcesCard, GradeKnownSourcesCard } from './SourceHousekeeping'
import { useRecompute } from './recompute'

export const RELIABILITY = [
  ['A', 'A - Completely reliable'],
  ['B', 'B - Usually reliable'],
  ['C', 'C - Fairly reliable'],
  ['D', 'D - Not usually reliable'],
  ['E', 'E - Unreliable'],
  ['F', 'F - Cannot be judged'],
] as const

const TLP_OPTIONS: readonly { value: '' | Tlp; label: string }[] = [
  { value: '', label: '(no TLP)' },
  { value: 'clear', label: 'TLP:CLEAR' },
  { value: 'green', label: 'TLP:GREEN' },
  { value: 'amber', label: 'TLP:AMBER' },
  { value: 'amber-strict', label: 'TLP:AMBER+STRICT' },
  { value: 'red', label: 'TLP:RED' },
] as const

export function SourcesPage() {
  const { data, error, isLoading } = useSources()
  const update = useUpdateSource()
  const setTlp = useSetSourceTlp()
  const recompute = useRecompute()
  if (isLoading) return <Loading />
  if (error || !data) return <ErrorCard error={error} />
  const notice = recompute.notice
  return (
    <div className="space-y-6">
      {/* One notice for the page: a rescore changes every number on every page, so it is not
          news about whichever card queued it. Rendered unconditionally — an aria-live region has
          to be in the DOM before its text arrives or the change is never announced. */}
      <p className={notice ? `text-sm ${notice.ok ? 'text-emerald-400' : 'text-yellow-400'}` : undefined}
        role="status">
        {notice?.text}
      </p>
      {/* What needs a decision, before the table that merely lists. Each renders nothing when
          there is nothing to decide. */}
      <GradeKnownSourcesCard recompute={recompute} />
      <DuplicateSourcesCard recompute={recompute} />
      <Card title="Sources">
      <p className="text-xs text-gray-400 mb-4">
        Admiralty source reliability per publisher. Changing it recomputes the confidence of every fact.
      </p>
      {update.error && <p className="text-sm text-red-400 mb-3" role="alert">{update.error.message}</p>}
      {data.length === 0 ? (
        <EmptyState>No sources yet. They appear after the first investigation or ingest.</EmptyState>
      ) : (
        <table className="data-table w-full">
          <thead><tr><th>Publisher</th><th>Domain</th><th>Documents</th><th>Reliability</th><th>TLP</th></tr></thead>
          <tbody>
            {data.map((source) => (
              <tr key={source.id}>
                <td>
                  {source.name}
                  {!!source.also_known_as?.length && (
                    <div className="text-[11px] text-gray-500">
                      also: {source.also_known_as.join(', ')}
                    </div>
                  )}
                </td>
                <td className="text-gray-400">{source.domain ?? '-'}</td>
                <td>{source.documents}</td>
                <td>
                  <select className="select" aria-label={`Reliability of ${source.name}`} value={source.reliability}
                    disabled={update.isPending}
                    onChange={(event) => {
                      recompute.reset()
                      update.mutate(
                        { id: source.id, reliability: event.target.value },
                        {
                          onSuccess: (result) =>
                            recompute.follow(`${result.name} set to ${result.reliability}`, result.job),
                        },
                      )
                    }}>
                    {RELIABILITY.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                  </select>
                </td>
                <td>
                  <select className="select" aria-label={`TLP of ${source.name}`} value={source.tlp ?? ''}
                    disabled={setTlp.isPending}
                    onChange={(event) => {
                      const value = event.target.value as '' | Tlp
                      setTlp.mutate({ id: source.id, tlp: value === '' ? null : value })
                    }}>
                    {TLP_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      </Card>
    </div>
  )
}
