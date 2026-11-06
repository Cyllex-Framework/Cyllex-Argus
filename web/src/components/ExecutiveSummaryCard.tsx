import { useState } from 'react'
import { useThreatSummary, useWriteThreatSummary } from '../api/hooks'
import { formatDateTime } from '../lib/format'

/** Roughly six lines at the card's width; past this the summary is clamped behind a toggle. */
const LONG_SUMMARY_CHARS = 600

/**
 * The answer, above the evidence.
 *
 * Every other card on a profile shows pieces — techniques, malware, citations, counts — and
 * leaves the operator to assemble the verdict. This one carries the prose verdict Argus already
 * knows how to write (`exporters/summary.py`, assessments only, never raw document text), which
 * until now was reachable only by downloading a Markdown export.
 *
 * It is deliberately the loudest element on the page: bigger type, no count badge, no table. The
 * complaint it answers is not "too much data" but "nothing claims to be the headline".
 *
 * Reading never calls the LLM. Writing does, so it is always an explicit click — except at the
 * end of an investigation, where the pipeline writes one so the dashboard opens with an answer
 * instead of a button.
 */
export function ExecutiveSummaryCard({ threatId }: { threatId: string }) {
  const { data, isLoading } = useThreatSummary(threatId)
  const write = useWriteThreatSummary(threatId)
  const [expanded, setExpanded] = useState(false)
  // A rich actor produces a long summary: 139 facts on Scattered Spider came back as 352 words
  // in one paragraph. Printed in full that is a twenty-line wall of text at the very top of the
  // page — which is the problem this card exists to solve, not a smaller version of it. Clamp
  // the headline to six lines and let the operator open the rest.
  const long = (data?.summary?.length ?? 0) > LONG_SUMMARY_CHARS
  const newFacts =
    data?.written_from_fact_count !== null && data?.written_from_fact_count !== undefined
      ? data.fact_count - data.written_from_fact_count
      : 0

  return (
    <section aria-labelledby="executive-summary-h" className="card p-5 border-l-2 border-l-gray-600">
      <div className="flex items-start justify-between gap-4 mb-3">
        <h2 id="executive-summary-h" className="text-xs font-semibold uppercase tracking-wide text-gray-400">
          Executive summary
        </h2>
        {data?.summary && (
          <button type="button" className="btn btn-secondary btn-sm shrink-0"
            onClick={() => write.mutate()} disabled={write.isPending}
            title="Rewrite the summary from the facts as they stand now (one LLM call)">
            {write.isPending ? 'Writing…' : data.stale ? 'Update' : 'Rewrite'}
          </button>
        )}
      </div>

      {isLoading ? (
        <p className="text-sm text-gray-400">Loading…</p>
      ) : data?.summary ? (
        <>
          <p className={`text-[15px] leading-relaxed text-gray-200 whitespace-pre-line${
            long && !expanded ? ' line-clamp-6' : ''
          }`}>
            {data.summary}
          </p>
          {long && (
            <button type="button" onClick={() => setExpanded(!expanded)}
              className="mt-2 text-xs text-cyan-400 hover:underline underline-offset-2"
              aria-expanded={expanded}>
              {expanded ? 'Show less' : 'Show the full summary'}
            </button>
          )}
          {data.stale && (
            <p className="mt-3 text-xs text-amber-400">
              {newFacts > 0
                ? `${newFacts} new fact${newFacts === 1 ? '' : 's'} since this was written — update to include ${newFacts === 1 ? 'it' : 'them'}.`
                : 'The facts have changed since this was written — update to refresh it.'}
            </p>
          )}
          <p className="mt-3 text-[11px] text-gray-500 font-mono">
            {formatDateTime(data.generated_at)} · from {data.written_from_fact_count} fact
            {data.written_from_fact_count === 1 ? '' : 's'}
            {data.model ? ` · ${data.model}` : ''}
          </p>
        </>
      ) : data?.can_generate ? (
        <div className="space-y-3">
          <p className="text-sm text-gray-400">
            No summary written yet. Argus can read the {data.fact_count} consolidated fact
            {data.fact_count === 1 ? '' : 's'} below and write the verdict — who this is, what it
            does, who it targets and how strong the evidence is.
          </p>
          <button type="button" className="btn btn-primary btn-sm"
            onClick={() => write.mutate()} disabled={write.isPending}>
            {write.isPending ? 'Writing…' : 'Write summary'}
          </button>
        </div>
      ) : (
        <p className="text-sm text-gray-500">
          Nothing to summarize yet — investigate this threat to collect quote-backed facts first.
        </p>
      )}

      {write.isError && (
        <p className="mt-3 text-xs text-red-400" role="alert">
          {write.error instanceof Error ? write.error.message : 'The summary could not be written.'}
        </p>
      )}
    </section>
  )
}
