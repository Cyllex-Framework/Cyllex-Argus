import { useEffect, useId, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { isActiveJob, useActiveJob, useCancelInvestigation, useInvestigation, useJobs, useStartJob } from '../../api/hooks'
import type { InvestigationDetail as Investigation, Job } from '../../api/types'
import { Card } from '../../components/Card'
import { PIPELINE_NEEDS, SetupNotice, useMissingPrerequisites } from '../../components/SetupNotice'
import { StatTile } from '../../components/StatTile'
import { JobStatePill } from '../../components/badges'
import { ErrorCard, Loading } from '../../components/QueryState'
import { formatDateTime } from '../../lib/format'
import { LivePipelineCard } from '../threats/LivePipelineCard'
import { InvestigationDocuments } from './InvestigationDocuments'
import { JobPanel } from './JobPanel'

const STAGES = ['collected', 'triaged', 'irrelevant', 'validated', 'failed']
const INVESTIGATION_JOBS = ['investigate', 'resume'] as const

/**
 * Whether a job works on this investigation: a resume of it, an investigate job that reported it, or an active
 * investigate job for its target (investigating a target again continues its unfinished investigation).
 */
export function concerns(job: Job, investigation: Pick<Investigation, 'id' | 'target'>): boolean {
  if (job.kind === 'resume') return Number(job.params.investigation_id) === investigation.id
  if (job.kind !== 'investigate') return false
  if (job.result?.investigation_id === investigation.id) return true
  return isActiveJob(job) && String(job.params.target ?? '').trim().toLowerCase() === investigation.target.trim().toLowerCase()
}

/**
 * Button that asks the pipeline to stop the current run cooperatively. The stop is not
 * instant — the pipeline checks the flag between docs. Letting operators cancel without a
 * dedicated UI was a long-standing UX gap: the previous workaround (delete the whole
 * investigation) also left the background job running and its logs ghosting on the panel.
 */
function StopButton({ investigationId }: { investigationId: number }) {
  const cancel = useCancelInvestigation()
  return (
    <button type="button" className="btn btn-secondary"
      onClick={() => cancel.mutate(investigationId)}
      disabled={cancel.isPending}>
      {cancel.isPending ? 'Stopping…' : 'Stop'}
    </button>
  )
}


/**
 * The router reuses this element when only `:id` changes, so the started job and its error live in a body keyed
 * on `id`: another investigation starts without the previous one's progress panel.
 */
export function InvestigationDetailPage() {
  const { id = '' } = useParams()
  return <InvestigationDetail key={id} id={id} />
}

function InvestigationDetail({ id }: { id: string }) {
  const { data, error, isLoading } = useInvestigation(id)
  const { data: jobs } = useJobs()
  const start = useStartJob()
  const [started, setStarted] = useState<string | null>(null)
  const jobId = useActiveJob(INVESTIGATION_JOBS, { started, matches: (job) => !!data && concerns(job, data) })
  const noticeId = useId()
  const blocked = useMissingPrerequisites(PIPELINE_NEEDS).length > 0
  const { reset } = start
  // Once the setup notice shows the missing prerequisite and its fix, the refusal that revealed it is stale: drop it,
  // so it does not come back when the fix is done.
  useEffect(() => {
    if (blocked) reset()
  }, [blocked, reset])
  if (isLoading) return <Loading />
  if (error || !data) return <ErrorCard error={error} />

  // A resume while an investigate or resume job for this investigation is queued or running would only repeat its work.
  const busy = (jobs ?? []).some((job) => isActiveJob(job) && concerns(job, data))
  const resume = () =>
    start.mutate({ kind: 'resume', investigation_id: data.id }, { onSuccess: (job) => setStarted(job.id) })

  const resumable = data.state !== 'finished'

  const showPausedBanner = data.state === 'paused' && !!data.paused_reason

  return (
    <div className="space-y-6">
      <Link to={`/investigations/${data.id}/dashboard`} className="inline-block text-sm text-purple-400 hover:underline">
        View analysis dashboard
      </Link>
      {showPausedBanner && (
        <div role="status" className="rounded border border-amber-700/40 bg-amber-900/20 p-3 text-sm text-amber-200">
          <div className="font-semibold mb-1">Investigation paused</div>
          <p className="text-amber-300/90">{data.paused_reason}</p>
          <p className="mt-2 text-amber-300/60 text-xs">
            Click <strong>Resume</strong> to continue from where the pipeline stopped —
            documents that already have claims are skipped automatically.
          </p>
        </div>
      )}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold break-words">#{data.id} {data.target}</h1>
          <div className="flex flex-wrap items-center gap-3 mt-2 text-sm text-gray-400">
            <JobStatePill state={data.state} />
            <span>Started {formatDateTime(data.started_at)}</span>
            {data.finished_at && <span>Finished {formatDateTime(data.finished_at)}</span>}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {busy && <StopButton investigationId={data.id} />}
          {resumable && (
            <button type="button" className="btn btn-primary" onClick={resume} disabled={busy || start.isPending || blocked}
              aria-describedby={blocked ? noticeId : undefined}>
              Resume
            </button>
          )}
        </div>
      </div>
      {resumable && <SetupNotice id={noticeId} needs={PIPELINE_NEEDS} purpose="resume this investigation" />}
      {start.error && !blocked && <p role="alert" className="text-sm text-red-400">{start.error.message}</p>}
      <JobPanel key={jobId ?? 'none'} jobId={jobId}
        title={jobs?.find((job) => job.id === jobId)?.kind === 'investigate' ? 'Investigation progress' : 'Resume progress'} />
      <LivePipelineCard investigationId={data.id} />
      <div className="grid grid-cols-5 gap-4">
        {STAGES.map((stage) => (
          <StatTile key={stage} label={stage} value={data.stage_counts[stage] ?? 0} />
        ))}
      </div>
      <Card title="Documents">
        <InvestigationDocuments documents={data.documents} />
      </Card>
      {data.failures.length > 0 && (
        <Card title="Failures">
          <ul className="space-y-2 text-sm">
            {data.failures.map((failure, index) => (
              <li key={index}>
                <span className="text-gray-200">{failure.title}</span>
                <span className="block text-xs text-red-400">{failure.reason}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  )
}
