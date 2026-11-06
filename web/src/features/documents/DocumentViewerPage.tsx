import { useMemo, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useDocument } from '../../api/hooks'
import { Card } from '../../components/Card'
import { StagePill } from '../../components/badges'
import { ExternalLink } from '../../components/ExternalLink'
import { ErrorCard, Loading } from '../../components/QueryState'
import { formatDate } from '../../lib/format'
import { segmentText, toUtf16Spans } from './highlight'

const QUOTE_STATUS: Record<string, string> = {
  verified: 'text-green-400',
  verified_fuzzy: 'text-yellow-400',
  rejected: 'text-red-400',
}

/** The router reuses this element when only `:id` changes, so the selected claim lives in a body keyed on `id`. */
export function DocumentViewerPage() {
  const { id = '' } = useParams()
  return <DocumentViewer key={id} id={id} />
}

function DocumentViewer({ id }: { id: string }) {
  const { data, error, isLoading } = useDocument(id)
  const [active, setActive] = useState<number | null>(null)
  const body = useRef<HTMLDivElement>(null)
  const segments = useMemo(() => {
    if (!data) return []
    // The API reports spans in code points; the text is indexed in UTF-16 units.
    const spans = data.claims.flatMap((claim) => (claim.span ? [{ id: claim.id, start: claim.span[0], end: claim.span[1] }] : []))
    return segmentText(data.text, toUtf16Spans(data.text, spans))
  }, [data])

  if (isLoading) return <Loading />
  if (error || !data) return <ErrorCard error={error} />

  const selectClaim = (claimId: number) => {
    setActive(claimId)
    body.current?.querySelector(`mark[data-claims~="${claimId}"]`)?.scrollIntoView?.({ block: 'center', behavior: 'smooth' })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold break-words">{data.title}</h1>
        <div className="flex flex-wrap items-center gap-3 mt-2 text-sm text-gray-400">
          <span>{data.publisher}</span>
          <StagePill stage={data.stage} />
          <span>{data.published_at ? formatDate(data.published_at) : 'undated'}</span>
          <ExternalLink href={data.location} />
        </div>
        {data.failure_reason && (
          <div role="alert" className="mt-3 text-sm text-red-400">Failed: {data.failure_reason}</div>
        )}
      </div>
      <div className="grid grid-cols-3 gap-6">
        <Card title="Text" className="col-span-2">
          {data.text ? (
            // `whitespace-pre-wrap` keeps the extracted text's own paragraph breaks (\n\n)
            // and single line breaks, so the article reads like prose instead of a wall.
            // Serif body copy at a comfortable reading size with a max-width around 72ch
            // is far more readable than the previous mono dump, and the <mark> highlights
            // still land on the same code-point indices the Analyst reported — segments
            // are character-indexed, not line-indexed, so the typography switch is safe.
            <div ref={body} data-testid="document-text"
                 className="font-serif text-[15px] leading-relaxed whitespace-pre-wrap break-words
                            max-w-[72ch] max-h-[70vh] overflow-y-auto text-gray-200 pr-2">
              {segments.map((segment, index) =>
                segment.ids.length === 0 ? (
                  <span key={index}>{segment.text}</span>
                ) : (
                  <mark key={index} data-claims={segment.ids.join(' ')} data-active={active !== null && segment.ids.includes(active) ? 'true' : 'false'}
                    onClick={() => setActive(segment.ids[0])}
                    className={`cursor-pointer rounded-sm px-0.5 ${active !== null && segment.ids.includes(active) ? 'bg-purple-500/60 text-white' : 'bg-yellow-500/25 text-gray-100'}`}>
                    {segment.text}
                  </mark>
                ),
              )}
            </div>
          ) : (
            <p className="text-sm text-gray-400">No extracted text for this document.</p>
          )}
        </Card>
        <section aria-label="Claims">
          <Card title={`Claims (${data.claims.length})`}>
            {data.claims.length === 0 ? (
              <p className="text-sm text-gray-400">No claims were extracted from this document.</p>
            ) : (
              <ul className="space-y-2">
                {data.claims.map((claim) => (
                  <li key={claim.id}>
                    <button type="button" aria-pressed={active === claim.id} onClick={() => selectClaim(claim.id)}
                      className={`w-full text-left p-2 rounded border ${active === claim.id ? 'border-purple-500 bg-gray-700/50' : 'border-gray-700 hover:bg-gray-700/30'}`}>
                      <span className="block text-sm text-gray-200">{claim.subject} {claim.predicate} {claim.object}</span>
                      <span className="block text-xs text-gray-400 mt-1">"{claim.quote}"</span>
                      <span className="block text-xs mt-1">
                        <span className={QUOTE_STATUS[claim.quote_status] ?? 'text-gray-400'}>{claim.quote_status}</span>
                        {claim.polarity === 'refutes' && <span className="text-red-400"> · refutes</span>}
                      </span>
                      {!claim.span && <span className="block text-xs text-gray-500 mt-1">Quote not located in the text</span>}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </section>
      </div>
    </div>
  )
}
