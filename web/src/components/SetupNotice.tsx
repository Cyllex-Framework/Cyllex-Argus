import { useEffect, useId, useState } from 'react'
import { isActiveJob, useActiveJob, useJobs, useSettings, useStartJob } from '../api/hooks'
import type { Settings } from '../api/types'
import { JobPanel } from '../features/investigations/JobPanel'

export type Prerequisite = 'attack' | 'claude'

/** Investigating, resuming and ingesting all run the pipeline: it maps techniques to ATT&CK and analyzes with Claude. */
export const PIPELINE_NEEDS: readonly Prerequisite[] = ['attack', 'claude']

const ATTACK_UPDATE = ['attack_update'] as const

function missingFrom(settings: Settings | undefined, needs: readonly Prerequisite[]): Prerequisite[] {
  if (!settings) return [] // unknown until the settings load: the server still refuses, and that refusal refreshes them
  return needs.filter((need) => (need === 'attack' ? !settings.attack.present : !settings.claude.found))
}

/** The prerequisites among `needs` that the server reports missing. */
export function useMissingPrerequisites(needs: readonly Prerequisite[]): Prerequisite[] {
  const { data } = useSettings()
  return missingFrom(data, needs)
}

function AttackStep() {
  const start = useStartJob()
  // Follows an update started anywhere (Settings, another page), so this notice never offers a second one, and
  // remembers it once it ends, so a failure stays on screen next to the retry.
  const [followed, setFollowed] = useState<string | null>(null)
  const jobId = useActiveJob(ATTACK_UPDATE, { started: followed, latest: false })
  useEffect(() => {
    if (jobId) setFollowed(jobId)
  }, [jobId])
  const { data: jobs } = useJobs()
  const job = jobs?.find((candidate) => candidate.id === jobId)
  // A job just started here may not be in the job list yet; it counts as running until the list says otherwise.
  const running = jobId !== null && (job ? isActiveJob(job) : true)
  const failed = job?.state === 'failed'
  return (
    <li className="space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-gray-100">MITRE ATT&CK data is missing</h3>
          <p className="mt-1 text-sm text-gray-300">
            Argus maps the techniques it finds in reports to MITRE ATT&CK, so it needs a local copy of the ATT&CK data.
            Download it once here; you can refresh it later from Settings.
          </p>
        </div>
        {!running && (
          <button type="button" className="btn btn-primary btn-sm" disabled={start.isPending}
            onClick={() => start.mutate({ kind: 'attack_update' }, { onSuccess: (created) => setFollowed(created.id) })}>
            {failed ? 'Retry ATT&CK update' : 'Update ATT&CK'}
          </button>
        )}
      </div>
      {start.error && <p role="alert" className="text-sm text-red-400">{start.error.message}</p>}
      <JobPanel key={jobId ?? 'none'} jobId={jobId} title="ATT&CK update" />
    </li>
  )
}

function ClaudeStep() {
  return (
    <li>
      <h3 className="text-sm font-semibold text-gray-100">Claude Code CLI not found</h3>
      <p className="mt-1 text-sm text-gray-300">
        Argus analyzes documents with Claude Code, using your Claude subscription. Install Claude Code, run{' '}
        <code className="mono">claude</code> once to log in, make sure <code className="mono">claude</code> is on your
        PATH, then restart <code className="mono">argus serve</code> and reload this page.
      </p>
    </li>
  )
}

/**
 * Lead the way when something a page needs is missing: one warning card listing each missing prerequisite with its
 * fix (the ATT&CK update runs right here; Claude Code must be installed outside Argus). It renders nothing once every
 * prerequisite is in place, and a finished update refreshes the settings, so the card goes away on its own. `id`
 * lets a disabled button point at it with `aria-describedby`.
 */
export function SetupNotice({ id, needs, purpose, title = 'Finish setup' }: {
  id?: string
  needs: readonly Prerequisite[]
  /** What the missing prerequisites block, completing "Argus needs this before it can ...". */
  purpose: string
  title?: string
}) {
  const missing = useMissingPrerequisites(needs)
  const headingId = useId()
  if (missing.length === 0) return null
  return (
    <section id={id} aria-labelledby={headingId} className="card p-5 border-yellow-700/30 bg-yellow-900/20">
      <h2 id={headingId} className="text-xs font-semibold uppercase tracking-wide text-yellow-400">{title}</h2>
      <p className="mt-1 mb-4 text-sm text-yellow-300">
        Argus needs {missing.length === 1 ? 'this' : 'these'} before it can {purpose}.
      </p>
      <ul className="space-y-5">
        {missing.includes('attack') && <AttackStep />}
        {missing.includes('claude') && <ClaudeStep />}
      </ul>
    </section>
  )
}
