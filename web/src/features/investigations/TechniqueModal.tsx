import { useEffect, useRef, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { useTechniqueDetail, useThreat } from '../../api/hooks'
import type { Fact, ScopeParam, TechniqueDetail } from '../../api/types'
import { ErrorCard, Loading } from '../../components/QueryState'
import { formatDate } from '../../lib/format'
import { ConfidenceBar } from '../../components/badges'
import { hasAtomicRedTeamTests } from './atomicRedTeamTechniques'

const STATUS_LABEL: Record<string, string> = {
  corroborated: 'Corroborated', 'single-source': 'Single source', contested: 'Contested',
}
const STATUS_TONE: Record<string, string> = {
  corroborated: 'bg-emerald-700/40 text-emerald-200 border-emerald-700/60',
  'single-source': 'bg-amber-700/40 text-amber-200 border-amber-700/60',
  contested: 'bg-rose-700/40 text-rose-200 border-rose-700/60',
}

/**
 * Centered modal showing an observed technique's details, Cyllex-style: title + external id,
 * a two-column meta row (Tactic / Status), a short summary, and a "Citations (N)" list of each
 * verbatim quote with publisher, date and document link. Closes on Escape, backdrop click or X.
 */
export function TechniqueModal({ entityId, tacticName, scope, onClose }: {
  entityId: string
  tacticName: string
  scope?: ScopeParam
  onClose: () => void
}) {
  const closeButton = useRef<HTMLButtonElement>(null)
  const { data, error, isLoading } = useThreat(entityId, scope)

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    closeButton.current?.focus()
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  const entity = data?.entity ?? null
  const mitreUrl = entity?.external_id ? mitreTechniqueUrl(entity.external_id) : null
  // Techniques are objects of `uses` facts coming from the threat. Collect every fact whose object is this entity.
  const facts: Fact[] = (data?.facts ?? []).filter((fact) => fact.object.id === entityId)
  const totalCitations = facts.reduce((sum, fact) => sum + fact.citations.length, 0)
  const totalSources = facts[0]?.source_count ?? 0
  // Full MITRE metadata for this technique (description, platforms, detection, data sources).
  // Fetched independently so the Argus-citation render does not block on the catalog lookup.
  const technique = useTechniqueDetail(entity?.external_id ?? null)

  return createPortal(
    <>
      <div data-testid="technique-modal-backdrop" className="fixed inset-0 z-50 bg-black/60" onClick={onClose} aria-hidden="true" />
      <div role="dialog" aria-modal="true" aria-label={`Technique ${entity?.external_id ?? entityId}`}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
        <div className="pointer-events-auto bg-gray-900 border border-gray-700 rounded-lg shadow-2xl w-full max-w-2xl max-h-[85vh] overflow-y-auto">
          {/* HEADER ------------------------------------------------- */}
          <div className="flex items-start justify-between gap-3 p-6 pb-4">
            <div className="min-w-0">
              {isLoading ? (
                <div className="h-6 w-56 bg-gray-800 rounded animate-pulse" />
              ) : (
                <h2 className="text-xl font-semibold text-gray-100 break-words leading-tight">
                  {entity?.name ?? 'Technique'}
                </h2>
              )}
              {entity && (
                <p className="mt-1 text-sm text-gray-400 font-mono">
                  {entity.external_id ?? entity.stix_type}
                  {totalCitations > 0 && (
                    <span className="ml-1 text-gray-500">
                      ({totalCitations} citation{totalCitations === 1 ? '' : 's'})
                    </span>
                  )}
                </p>
              )}
            </div>
            <button ref={closeButton} type="button" aria-label="Close"
              className="shrink-0 text-gray-400 hover:text-gray-100 text-2xl leading-none p-1"
              onClick={onClose}>
              ×
            </button>
          </div>

          {isLoading && <div className="px-6 pb-6"><Loading /></div>}
          {error && !isLoading && <div className="px-6 pb-6"><ErrorCard error={error} /></div>}

          {!isLoading && !error && entity && (
            <div className="px-6 pb-6 space-y-5">
              {/* META CARDS ----------------------------------------- */}
              <div className="grid grid-cols-2 gap-3">
                <MetaCard title="Tactic" value={tacticName} />
                <MetaCard title="Status" value={
                  facts.length === 0 ? <span className="text-gray-400 text-sm">No facts</span> : (
                    <span className={`inline-block text-xs font-semibold uppercase tracking-wide px-2 py-0.5 rounded border ${STATUS_TONE[facts[0].status] ?? ''}`}>
                      {STATUS_LABEL[facts[0].status] ?? facts[0].status}
                    </span>
                  )
                } />
              </div>

              {facts.length > 0 && (
                <div className="grid grid-cols-3 gap-3">
                  <MetaCard title="Confidence" value={<ConfidenceBar value={facts[0].confidence} />} />
                  <MetaCard title="Admiralty" value={<span className="font-mono text-sm">{facts[0].admiralty}</span>} />
                  <MetaCard title="Sources" value={<span className="text-sm">{totalSources}</span>} />
                </div>
              )}

              {/* DESCRIPTION / SUMMARY ------------------------------ */}
              <section>
                <h3 className="text-sm font-semibold text-gray-200 mb-2">Description</h3>
                <p className="text-sm text-gray-400 leading-relaxed">
                  {facts.length === 0 ? (
                    'No Argus evidence recorded for this threat. The cell is included because the technique exists in the MITRE ATT&CK catalog.'
                  ) : (
                    <>
                      Observed in <span className="text-gray-200">{facts.length} fact{facts.length === 1 ? '' : 's'}</span>
                      {' '}from <span className="text-gray-200">{totalSources} source{totalSources === 1 ? '' : 's'}</span>
                      {facts[0].first_seen && (
                        <>, first seen <span className="text-gray-200">{formatDate(facts[0].first_seen)}</span></>
                      )}
                      {facts[0].last_seen && facts[0].last_seen !== facts[0].first_seen && (
                        <>, last seen <span className="text-gray-200">{formatDate(facts[0].last_seen)}</span></>
                      )}.
                    </>
                  )}
                </p>
              </section>

              {/* CITATIONS ------------------------------------------ */}
              {totalCitations > 0 && (
                <section>
                  <h3 className="text-sm font-semibold text-gray-200 mb-2">
                    Citations ({totalCitations})
                  </h3>
                  <ul className="space-y-2">
                    {facts.flatMap((fact) => fact.citations.map((citation) => ({ fact, citation })))
                      .map(({ fact, citation }, index) => (
                        <li key={`${fact.predicate}|${citation.claim_id}|${index}`}
                          className="border border-gray-800 bg-gray-800/30 rounded p-3">
                          <blockquote className="text-sm text-gray-200 leading-relaxed">
                            "{citation.quote}"
                          </blockquote>
                          <div className="flex items-center justify-between mt-2 text-xs text-gray-400 flex-wrap gap-2">
                            <div className="flex items-center gap-2">
                              <span className="text-gray-300">{citation.publisher}</span>
                              <span>·</span>
                              <span>{citation.published_at ? formatDate(citation.published_at) : 'undated'}</span>
                              {citation.polarity === 'refutes' && (
                                <>
                                  <span>·</span>
                                  <span className="text-red-400">refutes</span>
                                </>
                              )}
                              {citation.quote_status === 'verified_fuzzy' && (
                                <>
                                  <span>·</span>
                                  <span className="text-yellow-400">approximate</span>
                                </>
                              )}
                            </div>
                          </div>
                          <div className="mt-1 text-xs text-gray-500 truncate flex items-center gap-2" title={citation.document_title}>
                            <span className="truncate">{citation.document_title}</span>
                            {citation.location && (
                              <a href={citation.location} target="_blank" rel="noopener noreferrer"
                                className="text-purple-400 hover:underline shrink-0">
                                open →
                              </a>
                            )}
                          </div>
                        </li>
                      ))}
                  </ul>
                </section>
              )}

              {/* MITRE TECHNICAL DETAILS --------------------------- */}
              {technique.data && <MitreDetails detail={technique.data} />}
              {technique.isLoading && !technique.data && (
                <section className="pt-2">
                  <div className="h-4 w-40 bg-gray-800 rounded animate-pulse" />
                </section>
              )}

              {/* FOOTER --------------------------------------------- */}
              <div className="pt-2 border-t border-gray-800 flex items-center gap-4 flex-wrap">
                {mitreUrl && (
                  <a href={mitreUrl} target="_blank" rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sm text-purple-400 hover:underline">
                    View on MITRE ATT&CK →
                  </a>
                )}
                {entity?.external_id && hasAtomicRedTeamTests(entity.external_id) && (
                  <a href={atomicRedTeamUrl(entity.external_id)} target="_blank" rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sm text-purple-400 hover:underline"
                    title="Executable tests for this technique on the Atomic Red Team project">
                    Atomic Red Team tests →
                  </a>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </>,
    document.body,
  )
}

function MetaCard({ title, value }: { title: string; value: React.ReactNode }) {
  return (
    <div className="border border-gray-800 bg-gray-800/30 rounded p-3">
      <div className="text-xs uppercase tracking-wide text-gray-500 mb-1">{title}</div>
      <div className="text-sm text-gray-200">{value}</div>
    </div>
  )
}

function mitreTechniqueUrl(externalId: string): string | null {
  const match = /^T(\d{4})(?:\.(\d{3}))?$/.exec(externalId)
  if (!match) return null
  const [, base, sub] = match
  return sub
    ? `https://attack.mitre.org/techniques/T${base}/${sub}/`
    : `https://attack.mitre.org/techniques/T${base}/`
}

/** Atomic Red Team hosts executable test cases per MITRE technique id (one YAML plus a markdown summary). */
function atomicRedTeamUrl(externalId: string): string {
  // Sub-techniques keep the dot in Atomic Red Team's folder names (T1078.004 → T1078.004/T1078.004.md).
  return `https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/${externalId}/${externalId}.md`
}

function MitreDetails({ detail }: { detail: TechniqueDetail }) {
  const { description, platforms, data_sources, permissions_required, detection } = detail
  const hasAny = description || platforms.length || data_sources.length || permissions_required.length || detection
  if (!hasAny) return null
  return (
    <section className="pt-3 border-t border-gray-800 space-y-4">
      <h3 className="text-sm font-semibold text-gray-200">MITRE technical details</h3>
      {description && (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-1">Description</h4>
          <MarkdownParagraphs text={description} />
        </div>
      )}
      <div className="grid grid-cols-2 gap-3">
        {platforms.length > 0 && <MetaField title="Platforms" items={platforms} />}
        {permissions_required.length > 0 && <MetaField title="Permissions required" items={permissions_required} />}
      </div>
      {data_sources.length > 0 && <MetaField title="Data sources" items={data_sources} wide />}
      {detection && (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-1">Detection</h4>
          <MarkdownParagraphs text={detection} />
        </div>
      )}
    </section>
  )
}

function MetaField({ title, items, wide }: { title: string; items: string[]; wide?: boolean }) {
  return (
    <div className={wide ? 'col-span-2' : ''}>
      <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-1">{title}</h4>
      <ul className="flex flex-wrap gap-1.5">
        {items.map((item) => (
          <li key={item} className="text-xs bg-gray-800 border border-gray-700 text-gray-200 rounded px-2 py-0.5">
            {item}
          </li>
        ))}
      </ul>
    </div>
  )
}

const INLINE = /<code>([\s\S]*?)<\/code>|`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\)/g

/** Render MITRE's inline markup as React nodes (built as elements, never a raw HTML string, so the
 *  injection guard holds): <code> and `backtick` spans become monospace, [text](url) becomes a link.
 *  Only http(s) URLs are linkified; anything else (e.g. a javascript: URL) stays literal text. */
export function renderInline(text: string): ReactNode[] {
  const nodes: ReactNode[] = []
  let last = 0
  let key = 0
  for (const m of text.matchAll(INLINE)) {
    const at = m.index ?? 0
    if (at > last) nodes.push(text.slice(last, at))
    const code = m[1] ?? m[2]
    if (code !== undefined) {
      nodes.push(<code key={key++} className="px-1 py-0.5 rounded bg-black/40 text-gray-200 text-[0.85em]">{code}</code>)
    } else if (/^https?:\/\//i.test(m[4])) {
      nodes.push(
        <a key={key++} href={m[4]} target="_blank" rel="noopener noreferrer" className="text-sky-400 hover:underline">{m[3]}</a>,
      )
    } else {
      nodes.push(m[0])
    }
    last = at + m[0].length
  }
  if (last < text.length) nodes.push(text.slice(last))
  return nodes
}

/** MITRE descriptions use markdown-ish prose with blank-line paragraphs and (Citation: X) refs. Render
 *  paragraphs, strip inline citation markers so they do not clutter the pane, and format inline code,
 *  backticks and [text](url) links (see renderInline). */
function MarkdownParagraphs({ text }: { text: string }) {
  const cleaned = text.replace(/\(Citation:[^)]*\)/g, '').replace(/\n{3,}/g, '\n\n').trim()
  const paragraphs = cleaned.split(/\n{2,}/)
  return (
    <div className="text-sm text-gray-300 space-y-2 leading-relaxed">
      {paragraphs.map((paragraph, index) => (
        <p key={index}>{paragraph.split('\n').map((line, lineIndex) => (
          <span key={lineIndex}>{lineIndex > 0 && <br />}{renderInline(line)}</span>
        ))}</p>
      ))}
    </div>
  )
}
