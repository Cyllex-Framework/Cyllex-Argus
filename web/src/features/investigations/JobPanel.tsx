import { useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, apiFetch } from '../../api/client'
import { useJobEvents } from '../../api/useJobEvents'
import { useQuery } from '@tanstack/react-query'
import { Card } from '../../components/Card'
import { JobStatePill } from '../../components/badges'

function time(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleTimeString()
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** True when the investigation the job targets has been deleted. The operator who hit
 * Delete expects the panel to update; without this check the old logs ghost on-screen. */
function useInvestigationExists(investigationId: number | null): boolean | null {
  const { data, error } = useQuery({
    queryKey: ['investigation-exists', investigationId],
    queryFn: () => apiFetch<unknown>(`/api/investigations/${investigationId}`).then(() => true),
    enabled: investigationId !== null,
    retry: false,
  })
  if (investigationId === null) return null
  if (error instanceof ApiError && error.status === 404) return false
  return data === true ? true : null
}

export function JobPanel({ jobId, title = 'Progress' }: { jobId: string | null; title?: string }) {
  const { events, job, ended, lost } = useJobEvents(jobId)
  const logRef = useRef<HTMLOListElement>(null)
  const stickToBottom = useRef(true)
  // Follow the tail as events stream in, but only while the reader is already at the bottom: if
  // they scroll up to read an earlier line, stop yanking them back down until they return.
  useEffect(() => {
    const el = logRef.current
    if (el && stickToBottom.current) el.scrollTop = el.scrollHeight
  }, [events.length])
  const onLogScroll = () => {
    const el = logRef.current
    if (el) stickToBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24
  }
  // Pull the investigation id from params first (available while the job is still queued/running)
  // and fall back to the result (available once the job finished). Either works.
  const paramsInvestigationId = typeof job?.params?.investigation_id === 'number'
    ? job.params.investigation_id : null
  const resultInvestigationId = typeof job?.result?.investigation_id === 'number'
    ? job.result.investigation_id : null
  const probedInvestigationId = paramsInvestigationId ?? resultInvestigationId
  const investigationExists = useInvestigationExists(probedInvestigationId)
  if (!jobId) return null
  const gone = ended && !job && !lost
  const investigationGone = investigationExists === false
  const state = investigationGone ? 'unknown'
    : job ? job.state : gone || lost ? 'unknown' : events.length > 0 ? 'running' : 'queued'
  const result = job?.result
  const investigationId = typeof result?.investigation_id === 'number' ? result.investigation_id : null
  const stageCounts = isPlainObject(result?.stage_counts) ? result.stage_counts : null
  return (
    <Card title={title} actions={<JobStatePill state={state} />}>
      {investigationGone && (
        <p className="text-yellow-400 text-sm">
          This investigation has been deleted. The pipeline is being stopped; whatever work it
          managed to complete has been removed with the investigation row.
        </p>
      )}
      {!investigationGone && events.length === 0 && !ended && <p className="text-gray-400 text-sm">Waiting for the job to start...</p>}
      {!investigationGone && gone && <p className="text-gray-400 text-sm">This job is no longer available.</p>}
      {!investigationGone && lost && (
        <p className="text-yellow-400 text-sm">
          Lost the connection to this job's progress. The server may have restarted; reload the page to check on it.
        </p>
      )}
      {!investigationGone && (
        <ol ref={logRef} onScroll={onLogScroll} className="mono text-xs space-y-1 max-h-80 overflow-y-auto">
          {events.map((event) => (
            <li key={event.seq} className="break-words">
              <span className="text-gray-500 mr-2">{time(event.time)}</span>
              <span className="text-gray-200">{event.message}</span>
            </li>
          ))}
        </ol>
      )}
      {!investigationGone && job?.message && <p className="mt-3 text-sm text-gray-300 break-words">{job.message}</p>}
      {!investigationGone && stageCounts && (
        <p className="mt-2 text-xs text-gray-400">
          {Object.entries(stageCounts).map(([stage, count]) => `${stage}: ${String(count)}`).join(' · ')}
        </p>
      )}
      {!investigationGone && investigationId !== null && (
        <Link to={`/investigations/${investigationId}/dashboard`} className="mt-2 inline-block text-sm text-purple-400 hover:underline">
          Open investigation #{investigationId}
        </Link>
      )}
    </Card>
  )
}
