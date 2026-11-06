import { useEffect, useId, useState, type FormEvent } from 'react'
import { useActiveJob, useIsReader, useStartJob } from '../../api/hooks'
import type { JobRequest } from '../../api/types'
import { Card } from '../../components/Card'
import { PIPELINE_NEEDS, SetupNotice, useMissingPrerequisites } from '../../components/SetupNotice'
import { JobPanel } from './JobPanel'

const STAGE_ORDER = ['collected', 'triaged', 'irrelevant', 'validated', 'failed']
const INVESTIGATE = ['investigate'] as const

export function stageSummary(counts: Record<string, number>): string {
  const stages = Object.keys(counts).sort((a, b) => {
    const rank = (stage: string) => (STAGE_ORDER.includes(stage) ? STAGE_ORDER.indexOf(stage) : STAGE_ORDER.length)
    return rank(a) - rank(b) || a.localeCompare(b)
  })
  return stages.length ? stages.map((stage) => `${stage} ${counts[stage]}`).join(' · ') : '-'
}

export function NewInvestigationCard() {
  const [target, setTarget] = useState('')
  const [maxDocs, setMaxDocs] = useState('')
  const [concurrency, setConcurrency] = useState(1)
  const [started, setStarted] = useState<string | null>(null)
  const jobId = useActiveJob(INVESTIGATE, { started })
  const start = useStartJob()
  const noticeId = useId()
  const blocked = useMissingPrerequisites(PIPELINE_NEEDS).length > 0
  const { reset } = start
  const isReader = useIsReader()
  // Once the setup notice shows the missing prerequisite and its fix, the refusal that revealed it is stale: drop it,
  // so it does not come back when the fix is done.
  useEffect(() => {
    if (blocked) reset()
  }, [blocked, reset])

  // Readers can browse investigations but not launch them; the server enforces this too (403).
  if (isReader) return null

  const submit = (event: FormEvent) => {
    event.preventDefault()
    const limit = Number(maxDocs) // not parseInt: "1e1" is ten, and parseInt would read it as one
    const base = { kind: 'investigate' as const, target: target.trim() }
    const withDocs = Number.isInteger(limit) && limit > 0 ? { ...base, max_docs: limit } : base
    const body: JobRequest = concurrency > 1 ? { ...withDocs, concurrency } : withDocs
    start.mutate(body, { onSuccess: (job) => setStarted(job.id) })
  }

  return (
    <div className="space-y-4">
      <SetupNotice id={noticeId} needs={PIPELINE_NEEDS} purpose="start an investigation" />
      <Card title="New investigation">
        <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
          <label className="flex-1 min-w-[16rem]">
            <span className="block text-xs text-gray-400 mb-1">Threat to investigate</span>
            <input className="input w-full" maxLength={200}
              placeholder="Actor, campaign, malware or CVE, e.g. Scattered Spider" value={target} onChange={(event) => setTarget(event.target.value)} />
          </label>
          <label className="w-48">
            <span className="block text-xs text-gray-400 mb-1">Maximum documents (optional)</span>
            <input className="input w-full" type="number" min={1} max={200}
              value={maxDocs} onChange={(event) => setMaxDocs(event.target.value)} />
          </label>
          <label className="w-40">
            <span className="block text-xs text-gray-400 mb-1" title="Documents the Analyst processes in parallel. Default 1; your Claude Code rate limits set the practical ceiling — 3-5 is a safe starting point.">
              Parallel workers
            </span>
            <input className="input w-full" type="number" min={1} max={16}
              aria-label="Parallel workers"
              value={concurrency}
              onChange={(event) => setConcurrency(Math.max(1, Math.min(16, Number(event.target.value) || 1)))} />
          </label>
          <button type="submit" className="btn btn-primary" disabled={!target.trim() || start.isPending || blocked}
            aria-describedby={blocked ? noticeId : undefined}>
            Start investigation
          </button>
        </form>
        {start.error && !blocked && <p role="alert" className="mt-3 text-sm text-red-400">{start.error.message}</p>}
        <p className="mt-3 text-xs text-gray-500">
          Argus searches the web and your feeds, then analyzes the documents with Claude. Nothing is sent anywhere else.
          {concurrency > 1 && ` ${concurrency} documents will be analysed in parallel.`}
        </p>
      </Card>
      <JobPanel key={jobId ?? 'none'} jobId={jobId} title="Investigation progress" />
    </div>
  )
}
