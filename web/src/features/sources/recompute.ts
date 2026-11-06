import { useState } from 'react'
import { useActiveJob } from '../../api/hooks'
import type { Job } from '../../api/types'
import { useJobEvents } from '../../api/useJobEvents'

const RECOMPUTE = ['recompute'] as const

/** The notice for a recompute job, after the change that queued it (`change` is null for one found in the job list). */
export function recomputeNotice(change: string | null, ended: boolean, job: Job | null): { text: string; ok: boolean } {
  if (!ended) return { text: change ? `${change}; recomputing confidences…` : 'Recomputing confidences…', ok: true }
  if (job?.state === 'finished' && job.result?.recomputed === false) {
    const missing = 'Confidences were not recomputed (ATT&CK data missing).'
    return { text: change ? `${change}. ${missing}` : missing, ok: false }
  }
  if (job?.state === 'finished') return { text: change ? `${change}; confidences recomputed.` : 'Confidences recomputed.', ok: true }
  const failure = job?.message ? `recomputing confidences failed: ${job.message}` : 'the outcome of recomputing confidences is unknown.'
  return { text: change ? `${change}, but ${failure}` : failure[0].toUpperCase() + failure.slice(1), ok: false }
}

/** What `useRecompute` hands to the controls that can move a confidence score. */
export interface Recompute {
  notice: { text: string; ok: boolean } | null
  reset: () => void
  follow: (what: string, job: Job) => void
}

/**
 * Follow the recompute a publisher change queued, and describe its outcome.
 *
 * One per page, handed to every control that can move a confidence score — the reliability
 * dropdown, the bulk grading card and the duplicate-merge card. An operator who just changed
 * the meaning of every number on screen has to be told when the numbers have caught up, and
 * silence there reads as "nothing happened".
 */
export function useRecompute(): Recompute {
  const [change, setChange] = useState<string | null>(null)
  // The recompute this page follows: the one a change queued, or an active one found in the job
  // list. Once found, it is kept after it ends, so its outcome stays on screen; an old finished
  // one is not announced on arrival.
  const [followed, setFollowed] = useState<string | null>(null)
  const jobId = useActiveJob(RECOMPUTE, { started: followed, latest: false })
  if (jobId !== null && jobId !== followed) setFollowed(jobId)
  const { job, ended } = useJobEvents(jobId)
  return {
    notice: jobId ? recomputeNotice(change, ended, job) : null,
    /** Call before mutating, so a previous outcome does not linger over the new action. */
    reset: () => { setChange(null); setFollowed(null) },
    /** Call on success with what changed, and the job that will rescore it. */
    follow: (what: string, job: Job) => { setChange(what); setFollowed(job.id) },
  }
}
