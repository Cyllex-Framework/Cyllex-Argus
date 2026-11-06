import { useEffect, useId, useState, type FormEvent } from 'react'
import { useActiveJob, useUpload } from '../../api/hooks'
import { Card } from '../../components/Card'
import { FileDropZone } from '../../components/FileDropZone'
import { PIPELINE_NEEDS, SetupNotice, useMissingPrerequisites } from '../../components/SetupNotice'
import { JobPanel } from '../investigations/JobPanel'

const MAX_FILES = 20
const INGEST = ['ingest'] as const

export function IngestCard() {
  const [files, setFiles] = useState<File[]>([])
  const [target, setTarget] = useState('')
  const [started, setStarted] = useState<string | null>(null)
  const jobId = useActiveJob(INGEST, { started })
  const upload = useUpload()
  const tooMany = files.length > MAX_FILES
  const noticeId = useId()
  const blocked = useMissingPrerequisites(PIPELINE_NEEDS).length > 0
  const { reset } = upload
  // Once the setup notice shows the missing prerequisite and its fix, the refusal that revealed it is stale: drop it,
  // so it does not come back when the fix is done.
  useEffect(() => {
    if (blocked) reset()
  }, [blocked, reset])

  const submit = (event: FormEvent) => {
    event.preventDefault()
    upload.mutate({ files, target }, {
      onSuccess: (job) => {
        setStarted(job.id)
        setFiles([])
      },
    })
  }

  return (
    <div className="space-y-4">
      <SetupNotice id={noticeId} needs={PIPELINE_NEEDS} purpose="ingest documents" />
      <Card title="Ingest documents">
        <form onSubmit={submit} className="space-y-3">
          <p className="text-sm text-gray-400">
            Reports and whitepapers you already have. They go through the same analysis, quote
            verification and scoring as anything Argus collected itself — a document you supply is
            not treated as more trustworthy than one it fetched.
          </p>
          {/* Deliberately NOT disabled while a prerequisite is missing: the operator picks
              their files, the submit button is disabled, and it points at the setup notice that
              says what to install. A picker that just refuses explains nothing. */}
          <FileDropZone multiple accept=".pdf,.html,.htm,.txt,.md"
            label="Choose files to ingest"
            hint={`PDF, HTML, text or Markdown · up to ${MAX_FILES} at a time`}
            selected={files}
            onFiles={(picked) => setFiles(picked)} />
          <input className="input w-full" aria-label="Focus threat (optional)" maxLength={200}
            placeholder="Focus threat (optional), e.g. Scattered Spider" value={target} onChange={(event) => setTarget(event.target.value)} />
          {tooMany && <p className="text-sm text-yellow-400">At most {MAX_FILES} files per upload.</p>}
          {upload.error && !blocked && <p role="alert" className="text-sm text-red-400">{upload.error.message}</p>}
          <button type="submit" className="btn btn-primary" disabled={files.length === 0 || tooMany || upload.isPending || blocked}
            aria-describedby={blocked ? noticeId : undefined}>
            {files.length ? `Ingest ${files.length} file(s)` : 'Ingest'}
          </button>
        </form>
      </Card>
      <JobPanel key={jobId ?? 'none'} jobId={jobId} title="Ingest progress" />
    </div>
  )
}
