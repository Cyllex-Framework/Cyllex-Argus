import { useEffect, useRef, useState } from 'react'
import type { KeyboardEvent } from 'react'
import { useDeleteTrace, useTrace, useTraceRaw } from '../../api/hooks'
import type { PipelineEvent } from '../../api/types'
import { Card } from '../../components/Card'
import { ErrorCard, Loading } from '../../components/QueryState'
import { formatDateTime } from '../../lib/format'

/** Short verb for an event's decision (the pipeline records `triaged-in`, `triaged-out`,
 *  `no-claims`, `refused`, ...). `refused` is a model safety-policy block, not a bug. */
export function decisionLabel(decision: string): string {
  if (decision === 'refused') return 'blocked by safety policy'
  return decision.replace(/^triaged-(in|out)$/, 'triaged $1')
}

const tone = (decision: string) =>
  decision === 'refused' ? 'text-amber-400' // policy block: amber, distinct from a red hard failure
    : decision === 'failed' || decision === 'rejected' ? 'text-red-400'
    : decision === 'triaged-out' ? 'text-gray-400' : 'text-green-400'

function groupByDocument(events: PipelineEvent[], titles: Map<number, string>): { key: string; title: string; events: PipelineEvent[] }[] {
  const general: PipelineEvent[] = []
  const docs = new Map<number, PipelineEvent[]>()
  for (const event of events) {
    if (event.document_id === null) general.push(event)
    else docs.set(event.document_id, [...(docs.get(event.document_id) ?? []), event])
  }
  return [
    ...(general.length ? [{ key: 'general', title: 'General', events: general }] : []),
    ...[...docs].map(([id, list]) => ({ key: `doc-${id}`, title: titles.get(id) || `Document #${id}`, events: list })),
  ]
}

function RawToggle({ investigationId, eventId }: { investigationId: string; eventId: number }) {
  const [open, setOpen] = useState(false)
  const { data, error, isLoading } = useTraceRaw(investigationId, eventId, open)
  return (
    <span className="ml-2">
      <button type="button" className="text-xs text-purple-400 hover:underline" aria-expanded={open}
        onClick={() => setOpen((value) => !value)}>
        {open ? 'Hide' : 'Show raw'}
      </button>
      {open && (
        <span className="block mt-2 space-y-2">
          {isLoading && <span className="block text-xs text-gray-400">Loading…</span>}
          {error && <span role="alert" className="block text-xs text-red-400">{error.message}</span>}
          {data && (
            <>
              <span className="block text-xs text-gray-400">Prompt</span>
              <pre className="whitespace-pre-wrap break-words text-xs">{data.prompt}</pre>
              <span className="block text-xs text-gray-400">Response</span>
              <pre className="whitespace-pre-wrap break-words text-xs">{data.response}</pre>
            </>
          )}
        </span>
      )}
    </span>
  )
}

function EventRow({ event, investigationId }: { event: PipelineEvent; investigationId: string }) {
  return (
    <li className="text-sm">
      <span className="text-gray-500 mr-2">{formatDateTime(event.created_at)}</span>
      <span className="text-gray-300 mr-2">{event.stage}</span>
      <span className={tone(event.decision)}>{decisionLabel(event.decision)}</span>
      {event.reason && <span className="text-gray-400 break-words"> ({event.reason})</span>}
      {event.usage && event.has_raw && <RawToggle investigationId={investigationId} eventId={event.id} />}
    </li>
  )
}

function ConfirmDelete({ onCancel, onConfirm, busy, error }: {
  onCancel: () => void
  onConfirm: () => void
  busy: boolean
  error: string | null
}) {
  const cancelRef = useRef<HTMLButtonElement>(null)
  const confirmRef = useRef<HTMLButtonElement>(null)
  useEffect(() => { cancelRef.current?.focus() }, [])
  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === 'Escape') onCancel()
    if (event.key !== 'Tab') return
    // Trap focus between the two buttons.
    const first = cancelRef.current
    const last = confirmRef.current
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onKeyDown={onKeyDown}>
      <div role="dialog" aria-modal="true" aria-labelledby="delete-trace-title" className="card p-5 max-w-md space-y-4">
        <h3 id="delete-trace-title" className="text-lg font-semibold">Delete pipeline trace?</h3>
        <p className="text-sm text-gray-300">This removes the trace for this investigation. The investigation itself and its facts stay.</p>
        {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
        <div className="flex justify-end gap-3">
          <button ref={cancelRef} type="button" onClick={onCancel} className="px-3 py-1.5 rounded text-sm bg-gray-700 hover:bg-gray-600">Cancel</button>
          <button ref={confirmRef} type="button" onClick={onConfirm} disabled={busy}
            className="px-3 py-1.5 rounded text-sm bg-red-700 hover:bg-red-600 disabled:opacity-50">Delete</button>
        </div>
      </div>
    </div>
  )
}

/** What the pipeline decided for each document, with the raw LLM text on demand. Collapsed by default. */
export function PipelineTrace({ investigationId }: { investigationId: string }) {
  const { data, error, isLoading } = useTrace(investigationId)
  const remove = useDeleteTrace(investigationId)
  const [expanded, setExpanded] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const events = data?.events ?? []
  const bodyId = `pipeline-trace-body-${investigationId}`

  const deleteButton = (
    <button type="button" disabled={events.length === 0} onClick={() => { remove.reset(); setConfirming(true) }}
      className="px-2 py-1 rounded text-xs bg-gray-700 hover:bg-gray-600 disabled:opacity-50">
      Delete pipeline trace
    </button>
  )
  return (
    <Card title="Pipeline trace" actions={deleteButton}>
      {isLoading ? <Loading /> : error || !data ? <ErrorCard error={error} /> : (
        <>
          <button type="button" aria-expanded={expanded} aria-controls={bodyId} onClick={() => setExpanded((value) => !value)}
            className="text-sm text-gray-300 hover:text-white">
            {expanded ? '▾' : '▸'} {events.length} {events.length === 1 ? 'event' : 'events'}
          </button>
          {expanded && (
            <div id={bodyId} className="mt-3 space-y-4">
              {events.length === 0 && <p className="text-sm text-gray-400">No trace recorded.</p>}
              {groupByDocument(events, new Map((data.documents ?? []).map((d) => [d.id, d.title]))).map((group) => (
                <div key={group.key}>
                  <h3 className="text-sm font-medium mb-1">{group.title}</h3>
                  <ul className="space-y-1">
                    {group.events.map((event) => <EventRow key={event.id} event={event} investigationId={investigationId} />)}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </>
      )}
      {confirming && (
        <ConfirmDelete busy={remove.isPending} error={remove.error ? remove.error.message : null}
          onCancel={() => setConfirming(false)}
          onConfirm={() => remove.mutate(undefined, { onSuccess: () => setConfirming(false) })} />
      )}
    </Card>
  )
}
