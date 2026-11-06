import type { Fact } from '../../api/types'
import { Card } from '../../components/Card'
import { ExternalLink } from '../../components/ExternalLink'
import { formatDate } from '../../lib/format'

/** Quotes, publishers and titles come from fetched documents: they are rendered as React text only. */
export function CitationsPanel({ fact }: { fact: Fact | null }) {
  return (
    <section aria-label="Citations">
      <Card title="Citations">
        {!fact ? (
          <p className="text-sm text-gray-400">Select a fact to see the quotes that support it.</p>
        ) : (
          <>
            <p className="text-sm mb-3">
              <span className="text-gray-200">{fact.subject.label}</span>{' '}
              <span className="text-gray-400">{fact.predicate}</span>{' '}
              <span className="text-gray-200">{fact.object.label}</span>
            </p>
            <ul className="space-y-3">
              {fact.citations.map((citation) => (
                <li key={citation.claim_id + citation.publisher + citation.quote} className="border-l-2 border-gray-700 pl-3">
                  <blockquote className="text-sm text-gray-200">"{citation.quote}"</blockquote>
                  <div className="text-xs text-gray-400 mt-1 space-x-2">
                    <span>{citation.publisher}</span>
                    <span>{citation.published_at ? formatDate(citation.published_at) : 'undated'}</span>
                    {citation.polarity === 'refutes' && <span className="text-red-400">refutes</span>}
                    {citation.quote_status === 'verified_fuzzy' && <span className="text-yellow-400">approximate match</span>}
                  </div>
                  <div className="text-xs mt-1">
                    <span className="text-gray-500">{citation.document_title} </span>
                    <ExternalLink href={citation.location} />
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}
      </Card>
    </section>
  )
}
