import { useDeferredValue, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useDocuments } from '../../api/hooks'
import { apiFetch } from '../../api/client'
import { Card } from '../../components/Card'
import { FileDropZone } from '../../components/FileDropZone'
import { StagePill } from '../../components/badges'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'
import { formatDate, formatDateTime } from '../../lib/format'
import { IngestCard } from './IngestCard'

const STAGES = ['', 'collected', 'triaged', 'irrelevant', 'validated', 'failed']

function RetryButton({ documentId }: { documentId: number }) {
  const queryClient = useQueryClient()
  const [feedback, setFeedback] = useState<string | null>(null)
  const [pendingVariant, setPendingVariant] = useState<'default' | 'browser' | null>(null)

  const mutation = useMutation({
    mutationFn: (asBrowser: boolean) => {
      const qs = asBrowser ? '?as_browser=1' : ''
      return apiFetch<{ job_id: unknown }>(`/api/documents/${documentId}/retry${qs}`, { method: 'POST' })
    },
    onSuccess: () => {
      setFeedback(pendingVariant === 'browser' ? 'queued (browser UA)' : 'queued')
      queryClient.invalidateQueries({ queryKey: ['documents'] })
      queryClient.invalidateQueries({ queryKey: ['jobs'] })
      setPendingVariant(null)
      setTimeout(() => setFeedback(null), 4000)
    },
    onError: (error: Error) => {
      setFeedback(error.message.slice(0, 60))
      setPendingVariant(null)
      setTimeout(() => setFeedback(null), 6000)
    },
  })

  const trigger = (variant: 'default' | 'browser') => {
    setPendingVariant(variant)
    mutation.mutate(variant === 'browser')
  }

  return (
    <div className="flex items-center gap-2">
      <button
        className="btn text-xs"
        onClick={() => trigger('default')}
        disabled={mutation.isPending}
        title="Re-run the pipeline (default Argus User-Agent)"
      >
        {mutation.isPending && pendingVariant === 'default' ? 'Retrying…' : 'Retry'}
      </button>
      <button
        className="btn text-xs"
        onClick={() => trigger('browser')}
        disabled={mutation.isPending}
        title="Retry with a Chrome-like User-Agent — for publishers (CISA, Trellix, …) whose WAF rejects bots"
      >
        {mutation.isPending && pendingVariant === 'browser' ? 'Retrying…' : 'as browser'}
      </button>
      {feedback && <span className="text-xs text-gray-400">{feedback}</span>}
    </div>
  )
}

/**
 * The way out of a refusal that retrying will not fix.
 *
 * A publisher's access policy, a page behind a login, a host that times out — those stay 403
 * however many times the button is pressed, and the document stays a hole in the evidence base
 * the dossier now has to declare. The operator can open the page in their own browser, save it,
 * and hand over the file: the SAME document row is repaired, so the URL, the publisher and the
 * investigations that collected it all survive.
 */
function SupplyFileControl({ documentId }: { documentId: number }) {
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [feedback, setFeedback] = useState<string | null>(null)
  // The picked file is tracked so the operator sees what they chose, and — the reason this
  // state exists at all — so clearing it on a refusal clears the native input too. Without
  // that, re-picking the same file after fixing the cause fires no `change` event and the
  // control silently does nothing.
  const [picked, setPicked] = useState<File[]>([])

  const mutation = useMutation({
    mutationFn: (file: File) => {
      const body = new FormData()
      body.append('file', file)
      return apiFetch<{ job_id: unknown }>(`/api/documents/${documentId}/supply`, { method: 'POST', body })
    },
    onSuccess: () => {
      setFeedback('queued — analysing your file')
      setOpen(false)
      setPicked([])
      queryClient.invalidateQueries({ queryKey: ['documents'] })
      queryClient.invalidateQueries({ queryKey: ['jobs'] })
      setTimeout(() => setFeedback(null), 6000)
    },
    onError: (error: Error) => {
      setFeedback(error.message.slice(0, 80))
      setPicked([])
    },
  })

  if (!open) {
    return (
      <div className="flex items-center gap-2">
        <button className="btn text-xs" onClick={() => { setFeedback(null); setOpen(true) }}
          title="Open the page in your own browser, save it, and give Argus the file — the same document is repaired in place">
          Upload the file
        </button>
        {feedback && <span className="text-xs text-gray-400">{feedback}</span>}
      </div>
    )
  }
  return (
    <div className="space-y-2">
      <FileDropZone accept=".pdf,.html,.htm,.txt,.md" disabled={mutation.isPending}
        label={mutation.isPending ? 'Uploading…' : 'Choose the saved page'}
        hint="Open the URL in your browser, save it, then give Argus that file."
        selected={picked}
        onFiles={(files) => {
          if (!files[0]) return
          setPicked(files)
          mutation.mutate(files[0])
        }} />
      <button className="btn text-xs" onClick={() => { setOpen(false); setPicked([]) }}
        disabled={mutation.isPending}>Cancel</button>
      {feedback && <p className="text-xs text-red-400" role="alert">{feedback}</p>}
    </div>
  )
}

export function DocumentsPage() {
  const [stage, setStage] = useState('')
  const [q, setQ] = useState('')
  const deferredQ = useDeferredValue(q)
  const { data, error, isLoading, isPlaceholderData } = useDocuments({ stage, q: deferredQ.trim() })
  return (
    <div className="space-y-6">
      <IngestCard />
      <Card title="Documents">
        <div className="flex gap-3 mb-4">
          <input className="input flex-1" aria-label="Search documents" placeholder="Search by title or publisher"
            value={q} onChange={(event) => setQ(event.target.value)} />
          <select className="select" aria-label="Filter by stage" value={stage} onChange={(event) => setStage(event.target.value)}>
            {STAGES.map((s) => <option key={s} value={s}>{s || 'All stages'}</option>)}
          </select>
        </div>
        {isLoading ? <Loading /> : error || !data ? <ErrorCard error={error} /> : (
          <div aria-busy={isPlaceholderData} className={isPlaceholderData ? 'opacity-60' : undefined}>
            {data.length === 0 ? (
              <EmptyState>No documents yet. Run an investigation or ingest files above.</EmptyState>
            ) : (
              <table className="data-table w-full">
                <thead><tr><th>Title</th><th>Publisher</th><th>Stage</th><th>Published</th><th>Retrieved</th><th></th></tr></thead>
                <tbody>
                  {data.map((doc) => (
                    <tr key={doc.id}>
                      <td>
                        <Link to={`/documents/${doc.id}`} className="text-purple-400 hover:underline">{doc.title}</Link>
                        {doc.failure_reason && <div className="text-xs text-red-400">{doc.failure_reason}</div>}
                      </td>
                      <td className="text-gray-400">{doc.publisher}</td>
                      <td><StagePill stage={doc.stage} /></td>
                      <td className="text-xs text-gray-400">{formatDate(doc.published_at)}</td>
                      <td className="text-xs text-gray-400">{formatDateTime(doc.retrieved_at)}</td>
                      <td>
                        {doc.stage === 'failed' && (
                          <div className="space-y-2">
                            <RetryButton documentId={doc.id} />
                            <SupplyFileControl documentId={doc.id} />
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
