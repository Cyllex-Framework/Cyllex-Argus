import { useEffect } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useCampaigns, useGraph, useInvestigation, useInvestigationDashboard, useThreat, useThreatSummary, useTrace } from '../../api/hooks'
import type { Campaign, DashboardInvestigation, DashboardEntity, Fact, GraphNode, Tactic } from '../../api/types'
import { ErrorCard, Loading } from '../../components/QueryState'
import { TokenUsageBadge } from '../../components/TokenUsageBadge'
import { compactNumber, formatCost, formatDate, formatDateTime } from '../../lib/format'

/**
 * Printable dossier for one investigation. Opens standalone (no app chrome, no sidebar). Every
 * section pulls data from the existing read endpoints; the browser's "Save as PDF" dialog produces
 * the final file. The media rule hides anything with the `no-print` class.
 */
export function InvestigationReport() {
  const { id = '' } = useParams()
  const dashboard = useInvestigationDashboard(id)
  const investigation = useInvestigation(id)
  const trace = useTrace(id)
  const entityId = dashboard.data?.entity?.id ?? null
  const threat = useThreat(entityId)
  const summary = useThreatSummary(entityId)
  const campaigns = useCampaigns(entityId)
  const graph = useGraph(entityId ?? '', 1, 200)

  useEffect(() => {
    document.title = dashboard.data?.entity?.name
      ? `Dossier — ${dashboard.data.entity.name}`
      : 'Investigation dossier'
    return () => { document.title = 'Cyllex Argus' }
  }, [dashboard.data?.entity?.name])

  if (dashboard.isLoading || investigation.isLoading) return <Loading />
  if (dashboard.error || !dashboard.data) return <ErrorCard error={dashboard.error} />

  const inv = dashboard.data.investigation
  const entity = dashboard.data.entity
  const coverage = coverageOf(inv.counts)

  return (
    <article className="report-root min-h-screen">
      <PrintToolbar />
      <PrintStyles />

      <section className="report-cover">
        <div className="report-logo">
          <img src={`${import.meta.env.BASE_URL}assets/argus-logo.png`} alt="Cyllex Argus" />
        </div>
        <p className="report-framework">AI-powered adversary intelligence framework</p>
        <hr className="report-rule" />
        <p className="report-eyebrow">Threat intelligence dossier</p>
        <h1 className="report-title">{entity ? entity.name : inv.target}</h1>
        {entity && (
          <p className="report-subtitle">
            {entity.stix_type}
            {entity.external_id && ` · ${entity.external_id}`}
            {entity.attack && ' · MITRE ATT&CK'}
          </p>
        )}
        <dl className="report-meta">
          <div><dt>Investigation</dt><dd>#{inv.id}</dd></div>
          <div><dt>State</dt><dd>{inv.state}</dd></div>
          <div><dt>Started</dt><dd>{formatDateTime(inv.started_at)}</dd></div>
          <div><dt>Finished</dt><dd>{formatDateTime(inv.finished_at) || '—'}</dd></div>
          <div><dt>Evidence base</dt><dd>
            {coverage.validated} of {coverage.collected} document{coverage.collected === 1 ? '' : 's'} read
          </dd></div>
          <div><dt>LLM usage</dt><dd>
            {compactNumber(inv.token_usage.total.total_tokens)} tokens · {formatCost(inv.token_usage.total.cost_usd)}
          </dd></div>
          <div><dt>Generated</dt><dd>{formatDateTime(new Date().toISOString())}</dd></div>
          <div><dt>Reference</dt><dd>ARGUS-{new Date().getFullYear()}-INV{inv.id}</dd></div>
        </dl>
        <div className="report-stats">
          {[
            { label: 'Techniques', value: dashboard.data.attack_matrix.tactics.reduce((n, t) => n + t.techniques.length, 0), cls: 'stat-neutral' },
            { label: 'Corroborated', value: (threat.data?.facts ?? []).filter((f) => f.status === 'corroborated').length, cls: 'stat-corroborated' },
            { label: 'Single source', value: (threat.data?.facts ?? []).filter((f) => f.status === 'single-source').length, cls: 'stat-single' },
            { label: 'Contested', value: (threat.data?.facts ?? []).filter((f) => f.status === 'contested').length, cls: 'stat-contested' },
          ].map((tile) => (
            <div key={tile.label} className={`report-stat ${tile.cls}`}>
              <span className="report-stat-value">{tile.value}</span>
              <span className="report-stat-label">{tile.label}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="report-section report-toc-page" aria-labelledby="toc">
        <h2 id="toc">Table of contents</h2>
        <ol className="report-toc">
          {TOC.filter((row) => row.always !== false || row.id !== 'summary' || !!summary.data?.summary).map((row) => (
            <li key={row.id}><a href={`#${row.id}`}>{row.label}</a></li>
          ))}
        </ol>
      </section>

      <CoverageNote coverage={coverage} />

      {entity && threat.data && (
        <>
          <ExecutiveSummarySection summary={summary.data?.summary ?? null}
            generatedAt={summary.data?.generated_at ?? null}
            stale={summary.data?.stale ?? false} />
          <AliasesSection entity={entity} />
          <ThreatProfileSection facts={threat.data.facts} entity={entity} />
          <AttackMatrixSection tactics={dashboard.data.attack_matrix.tactics} />
          <RelatedBlock facts={threat.data.facts} entityId={entity.id} graph={graph.data?.nodes ?? []} />
          <CampaignsSection campaigns={campaigns.data?.campaigns ?? []} />
          <IoCsSection graph={graph.data?.nodes ?? []} facts={threat.data.facts} entityId={entity.id} />
        </>
      )}
      {!entity && (
        <section className="report-section"><p>No target entity was resolved for this investigation.</p></section>
      )}

      <DocumentsSection documents={investigation.data?.documents ?? []} />
      <PipelineSection investigation={inv} eventsCount={trace.data?.events.length ?? 0} />
      <MethodologySection />

      <footer className="report-footer">
        <p>
          Dossier generated by <strong>Cyllex Argus</strong>. Every claim in this document is backed by a
          verbatim quote from a primary source and an Admiralty / confidence score. See the methodology
          section for how those scores are computed.
        </p>
      </footer>
    </article>
  )
}

interface Coverage { collected: number; validated: number; unreadable: number; offTopic: number }

/** The stage counts, read as an evidence base rather than as pipeline telemetry. */
function coverageOf(counts: Record<string, number>): Coverage {
  return {
    collected: Object.values(counts).reduce((total, n) => total + n, 0),
    validated: counts.validated ?? 0,
    unreadable: counts.failed ?? 0,
    offTopic: counts.irrelevant ?? 0,
  }
}

/**
 * What this dossier could not read, said on the cover.
 *
 * A dossier built from 25 of 40 documents looks exactly like one built from 25 of 25 — the
 * reader cannot tell from the findings, so the cover has to tell them. And it has to say what
 * the gap means: "we found no evidence of X" and "we could not read the sources that might
 * report X" are different claims, and only the first one is a finding. Stating that is the
 * difference between an honest intelligence product and a misleading one.
 */
function CoverageNote({ coverage }: { coverage: Coverage }) {
  if (coverage.unreadable === 0) return null
  const n = coverage.unreadable
  return (
    <p className="report-note report-coverage">
      <strong>Coverage limitation.</strong> {n} of {coverage.collected} collected document
      {coverage.collected === 1 ? '' : 's'} could not be retrieved or parsed and contributed no
      facts. A finding absent from this dossier may be absent from the reporting, or present only
      in a document this collection could not read; the dossier cannot tell the two apart.
    </p>
  )
}

/** `always: false` entries are printed only when the dossier actually has that content, so the
 *  contents list never promises a page that is not there. */
const TOC: readonly { id: string; label: string; always?: boolean }[] = [
  { id: 'summary', label: 'Executive summary', always: false },
  { id: 'aliases', label: 'Aliases' },
  { id: 'profile', label: 'Threat profile' },
  { id: 'matrix', label: 'MITRE ATT&CK techniques observed' },
  { id: 'related', label: 'Malware, tools, victims, vulnerabilities, locations' },
  { id: 'campaigns', label: 'Known campaigns' },
  { id: 'iocs', label: 'Indicators of compromise' },
  { id: 'documents', label: 'Document references' },
  { id: 'pipeline', label: 'Pipeline summary' },
  { id: 'methodology', label: 'Methodology' },
]

// -- Section components -----------------------------------------------------------------------------

/**
 * The verdict, first page after the contents.
 *
 * A dossier that opens on an alias list and never states the conclusion makes the reader do
 * the analysis the tool already did. This prints the cached executive summary, or nothing at
 * all when none was written — a print view must not offer to spend an LLM call, and an empty
 * "Executive summary" heading would be worse than no heading.
 */
function ExecutiveSummarySection({ summary, generatedAt, stale }: {
  summary: string | null
  generatedAt: string | null
  stale: boolean
}) {
  if (!summary) return null
  return (
    <section className="report-section" id="summary" aria-labelledby="summary-h">
      <h2 id="summary-h">Executive summary</h2>
      <p className="report-summary">{summary}</p>
      <p className="report-note">
        Written by Argus from the consolidated assessments in this dossier on {formatDateTime(generatedAt)}.
        {stale && ' Facts have been added since; the sections below are current, this summary is not.'}
      </p>
    </section>
  )
}

function AliasesSection({ entity }: { entity: DashboardEntity }) {
  if (entity.aliases.length === 0) return null
  const grouped = new Map<string, string[]>()
  for (const alias of entity.aliases) {
    const list = grouped.get(alias.origin) ?? []
    list.push(alias.alias)
    grouped.set(alias.origin, list)
  }
  return (
    <section id="aliases" className="report-section" aria-labelledby="aliases-h">
      <h2 id="aliases-h">Aliases</h2>
      <table className="report-table">
        <thead><tr><th>Origin</th><th>Known as</th></tr></thead>
        <tbody>
          {[...grouped.entries()].map(([origin, names]) => (
            <tr key={origin}>
              <td><span className="pill">{origin}</span></td>
              <td>{names.join(', ')}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

const STATUS_LABEL: Record<string, string> = {
  corroborated: 'Corroborated', 'single-source': 'Single source', contested: 'Contested',
}

function ThreatProfileSection({ facts, entity }: { facts: Fact[]; entity: DashboardEntity }) {
  if (facts.length === 0) return null
  const sorted = [...facts].sort(
    (a, b) => a.predicate.localeCompare(b.predicate) || b.confidence - a.confidence,
  )
  return (
    <section id="profile" className="report-section" aria-labelledby="profile-h">
      <h2 id="profile-h">Threat profile: assessed facts</h2>
      <p className="report-lede">
        {facts.length} assessed fact{facts.length === 1 ? '' : 's'} about <strong>{entity.name}</strong>. The verbatim
        quote and citation behind every fact are in the Markdown export.
      </p>
      <table className="report-table">
        <thead>
          <tr><th>Fact</th><th>Relationship</th><th>Status</th><th>Conf.</th><th>Src</th><th>Observed</th></tr>
        </thead>
        <tbody>
          {sorted.map((fact) => (
            <tr key={`${fact.subject.id}|${fact.predicate}|${fact.object.id}`}>
              <td><span className="subject">{fact.subject.label}</span> → <span className="object">{fact.object.label}</span></td>
              <td className="pred">{fact.predicate}</td>
              <td><span className={`status status-${fact.status}`}>{STATUS_LABEL[fact.status] ?? fact.status}</span></td>
              <td className="mono nowrap">{fact.confidence} · {fact.admiralty}</td>
              <td>{fact.source_count}</td>
              <td className="mono nowrap">{observedRange(fact)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

function observedRange(fact: Fact): string {
  const year = (d: string | null): string | null => (d ? d.slice(0, 4) : null)
  const a = year(fact.first_seen)
  const b = year(fact.last_seen)
  if (a && b) return a === b ? a : `${a}-${b}`
  return a ?? b ?? '—'
}

function AttackMatrixSection({ tactics }: { tactics: Tactic[] }) {
  const populated = tactics.filter((t) => t.techniques.length > 0)
  if (populated.length === 0) return null
  return (
    <section id="matrix" className="report-section" aria-labelledby="matrix-h">
      <h2 id="matrix-h">MITRE ATT&CK techniques observed</h2>
      <div className="matrix-grid">
        {populated.map((tactic) => (
          <div key={tactic.id} className="matrix-column">
            <h3 className="matrix-head">{tactic.name} <span className="count">({tactic.techniques.length})</span></h3>
            <ul>
              {tactic.techniques.map((tech) => (
                <li key={tech.id} className={`tech tech-${tech.status}`}>
                  <span className="tech-id">{tech.external_id}</span>
                  <span className="tech-name">{tech.name}</span>
                  <span className="tech-meta">{tech.sources} source{tech.sources === 1 ? '' : 's'} · {tech.admiralty}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </section>
  )
}

function RelatedBlock({ facts, entityId, graph }: { facts: Fact[]; entityId: string; graph: GraphNode[] }) {
  const linked = (type: string) => graph.filter((n) => n.id !== entityId && n.type === type)
  const malware = linked('malware')
  const tools = linked('tool')
  const identities = linked('identity')
  const locations = linked('location')
  const vulns = linked('vulnerability')
  if (!malware.length && !tools.length && !identities.length && !locations.length && !vulns.length) return null
  return (
    <section id="related" className="report-section" aria-labelledby="related-h">
      <h2 id="related-h">Malware, tools, victims, vulnerabilities, locations</h2>
      <div className="related-grid">
        {malware.length > 0 && <RelatedCard title="Malware" items={malware} />}
        {tools.length > 0 && <RelatedCard title="Tools" items={tools} />}
        {identities.length > 0 && <RelatedCard title="Targets & victims" items={identities} />}
        {vulns.length > 0 && <VulnCard items={vulns} facts={facts} />}
        {locations.length > 0 && <RelatedCard title="Targeted locations" items={locations} />}
      </div>
    </section>
  )
}

function RelatedCard({ title, items }: { title: string; items: GraphNode[] }) {
  return (
    <div className="related-card">
      <h3>{title} <span className="count">({items.length})</span></h3>
      <ul>{items.map((n) => <li key={n.id}>{n.label}</li>)}</ul>
    </div>
  )
}

function VulnCard({ items, facts }: { items: GraphNode[]; facts: Fact[] }) {
  // Map vulnerability id → entity it is exploited by (if a fact says so).
  const exploitedBy = new Map<string, string[]>()
  for (const fact of facts) {
    if (fact.predicate !== 'exploits') continue
    const list = exploitedBy.get(fact.object.id) ?? []
    list.push(fact.subject.label)
    exploitedBy.set(fact.object.id, list)
  }
  return (
    <div className="related-card">
      <h3>Vulnerabilities exploited <span className="count">({items.length})</span></h3>
      <ul>
        {items.map((n) => (
          <li key={n.id}>
            <strong>{n.label}</strong>
            {exploitedBy.get(n.id) && (
              <span className="exploited"> exploited by {exploitedBy.get(n.id)!.join(', ')}</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}

function CampaignsSection({ campaigns }: { campaigns: Campaign[] }) {
  if (campaigns.length === 0) return null
  return (
    <section id="campaigns" className="report-section" aria-labelledby="campaigns-h">
      <h2 id="campaigns-h">Known campaigns</h2>
      <table className="report-table">
        <thead><tr><th>Name</th><th>External ID</th><th>Period</th><th>TTPs</th></tr></thead>
        <tbody>
          {campaigns.map((campaign) => (
            <tr key={campaign.id}>
              <td>{campaign.name}</td>
              <td className="mono">{campaign.external_id ?? '—'}</td>
              <td>
                {campaign.first_seen ? formatDate(campaign.first_seen) : '—'}
                {campaign.last_seen && campaign.last_seen !== campaign.first_seen && (
                  <> → {formatDate(campaign.last_seen)}</>
                )}
              </td>
              <td>{campaign.techniques}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

function IoCsSection({ graph, facts, entityId }: { graph: GraphNode[]; facts: Fact[]; entityId: string }) {
  const iocs = graph.filter((n) => n.type === 'indicator')
  if (iocs.length === 0) return null
  // Group by inferred kind from the label (ipv4, domain, url, hash).
  const kind = (label: string): string => {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(label)) return 'IPv4'
    if (/^[a-f0-9]{32}$/i.test(label)) return 'MD5'
    if (/^[a-f0-9]{40}$/i.test(label)) return 'SHA-1'
    if (/^[a-f0-9]{64}$/i.test(label)) return 'SHA-256'
    if (/^https?:\/\//i.test(label)) return 'URL'
    if (/\./.test(label) && !/\s/.test(label)) return 'Domain'
    return 'Other'
  }
  const byKind = new Map<string, GraphNode[]>()
  for (const ioc of iocs) {
    const k = kind(ioc.label)
    const list = byKind.get(k) ?? []
    list.push(ioc)
    byKind.set(k, list)
  }
  // Which entity the IoC indicates — pull it from `indicates` facts if present.
  const indicatesLabel = new Map<string, string>()
  for (const fact of facts) {
    if (fact.predicate !== 'indicates') continue
    if (fact.subject.id !== entityId && fact.object.id === entityId) {
      indicatesLabel.set(fact.subject.id, fact.object.label)
    }
  }
  return (
    <section id="iocs" className="report-section" aria-labelledby="iocs-h">
      <h2 id="iocs-h">Indicators of compromise</h2>
      <p className="report-lede">{iocs.length} indicator{iocs.length === 1 ? '' : 's'} across {byKind.size} kind{byKind.size === 1 ? '' : 's'}.</p>
      {[...byKind.entries()].map(([k, items]) => (
        <section key={k} className="report-subsection">
          <h3>{k} <span className="count">({items.length})</span></h3>
          <ul className="ioc-list mono">
            {items.map((ioc) => (
              <li key={ioc.id}>
                <span className={`freshness freshness-${ioc.freshness ?? 'unknown'}`} aria-hidden="true" />
                {ioc.label}
                {ioc.freshness && <span className="ioc-meta"> · {ioc.freshness}</span>}
              </li>
            ))}
          </ul>
        </section>
      ))}
    </section>
  )
}

function DocumentsSection({ documents }: { documents: { id: number; title: string; publisher: string; stage: string; published_at: string | null; location: string | null }[] }) {
  if (documents.length === 0) return null
  return (
    <section id="documents" className="report-section" aria-labelledby="documents-h">
      <h2 id="documents-h">Document references</h2>
      <table className="report-table report-docs">
        <thead><tr><th>Publisher</th><th>Published</th><th>Title</th><th>Stage</th><th>Link</th></tr></thead>
        <tbody>
          {documents.map((doc) => (
            <tr key={doc.id}>
              <td>{doc.publisher}</td>
              <td>{doc.published_at ? formatDate(doc.published_at) : '—'}</td>
              <td>{doc.title}</td>
              <td><span className={`pill pill-${doc.stage}`}>{doc.stage}</span></td>
              <td>{doc.location ? <a className="link mono" href={doc.location}>{doc.location}</a> : '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

function PipelineSection({ investigation, eventsCount }: { investigation: DashboardInvestigation; eventsCount: number }) {
  const counts = Object.entries(investigation.counts ?? {})
  return (
    <section id="pipeline" className="report-section" aria-labelledby="pipeline-h">
      <h2 id="pipeline-h">Pipeline summary</h2>
      <table className="report-table">
        <tbody>
          <tr><th>Documents by stage</th><td>{counts.length === 0 ? '—' : counts.map(([k, v]) => `${v} ${k}`).join(' · ')}</td></tr>
          <tr><th>Pipeline events recorded</th><td>{eventsCount}</td></tr>
          <tr><th>LLM usage</th><td><TokenUsageBadge usage={investigation.token_usage} /></td></tr>
        </tbody>
      </table>
    </section>
  )
}

function MethodologySection() {
  return (
    <section id="methodology" className="report-section" aria-labelledby="methodology-h">
      <h2 id="methodology-h">Methodology</h2>
      <p>
        <strong>Collector</strong> searches primary sources on the web (vendor research, CERT advisories,
        incident reports), downloads them, and records the publisher and published date. Only
        LLM-generated queries leave the machine; document content never does.
      </p>
      <p>
        <strong>Triage</strong> decides whether each document is substantively about the target. Documents
        whose title does not mention the target and whose body mentions it only once are passed through
        the LLM for a final decision; anything else is handled deterministically.
      </p>
      <p>
        <strong>Analyst</strong> extracts atomic claims from each document with a verbatim supporting quote
        (20–400 characters, character-for-character exact). Predicates: <code>uses</code>, <code>attributed-to</code>,
        <code>targets</code>, <code>exploits</code>, <code>indicates</code>, <code>variant-of</code>, <code>alias-of</code>.
      </p>
      <p>
        <strong>Validator</strong> is purely deterministic. It verifies each quote against the source text
        (exact or 95% fuzzy match), resolves entity names to the knowledge base, and recomputes the
        confidence score and status.
      </p>
      <p>
        <strong>Status</strong> is derived from independent corroborating sources:
        <em> corroborated</em> ≥ 2 independent publishers assert; <em>single source</em> only one publisher asserts;
        <em>contested</em> one or more publishers refute. <strong>Confidence</strong> and{' '}
        <strong>Admiralty</strong> are composite scores based on publisher reliability, number of sources,
        recency and the quality of the quote match.
      </p>
    </section>
  )
}

// -- Print toolbar and CSS --------------------------------------------------------------------------

function PrintToolbar() {
  return (
    <div className="print-toolbar no-print" role="toolbar" aria-label="Dossier controls">
      <Link to="/investigations" className="link">← Back to investigations</Link>
      <div className="print-toolbar-actions">
        <button type="button" className="btn-print" onClick={() => window.print()}>
          Print / Save as PDF
        </button>
      </div>
    </div>
  )
}

function PrintStyles() {
  return <style>{PRINT_CSS}</style>
}

const PRINT_CSS = `
  /* Cyllex report aesthetic: dark field, cyan accent. Swap --accent to #9333ea for Argus-purple. */
  .report-root { --bg:#10152b; --panel:#182043; --panel-2:#1f2850; --border:#2c355f; --row:#222a4d;
    --accent:#2fd4f0; --text:#dfe3f0; --muted:#8b93b8; --faint:#6b74a0; --pass:#34d399; --amber:#fbbf24; --fail:#f87171; --warn:#e0a35a;
    max-width: 1000px; margin: 0 auto; padding: 1.5rem 2rem; background: var(--bg); color: var(--text);
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; line-height: 1.6;
    -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .report-root h1, .report-root h2, .report-root h3 { font-family: 'Inter', -apple-system, sans-serif; margin-top: 0; }
  .report-root a, .report-root .link { color: var(--accent); text-decoration: none; }
  .report-root a:hover { text-decoration: underline; }
  .report-root code { font-family: 'JetBrains Mono','Consolas',monospace; font-size: 0.85em; background: #0e1430; border: 1px solid var(--border); padding: 0.08em 0.4em; border-radius: 4px; color: #cfe8ff; }
  .mono { font-family: 'JetBrains Mono','Consolas',monospace; }

  .print-toolbar { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; margin: -1.5rem -2rem 1.5rem; border-bottom: 1px solid var(--border); background: #111226; }
  .print-toolbar-actions { display: flex; gap: 0.5rem; align-items: center; }
  .btn-print { padding: 0.5rem 1rem; background: var(--accent); color: #042630; border: none; border-radius: 6px; cursor: pointer; font-weight: 700; font-size: 0.9rem; }
  .btn-print:hover { filter: brightness(1.08); }

  /* Dark cover: logo (already a transparent PNG), title, reference block, headline counts. */
  .report-cover { margin: -1.5rem -2rem 1.75rem; padding: 3.25rem 2.5rem 3rem; min-height: 820px; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; background: linear-gradient(135deg, #141528 0%, #1f2850 100%); color: var(--text); border-bottom: 1px solid var(--border); page-break-after: always; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .report-logo { margin: 0 0 1.25rem; }
  .report-logo img { height: 64px; width: auto; display: block; }
  .report-framework { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.22em; color: var(--muted); margin: 0; font-family: 'Inter', sans-serif; }
  .report-rule { width: 170px; border: none; border-top: 1px solid var(--border); margin: 1.75rem 0; }
  .report-eyebrow { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.24em; color: var(--accent); font-weight: 700; margin: 0; font-family: 'Inter', sans-serif; }
  .report-title { font-size: 2.5rem; margin: 0.75rem 0 0.25rem; font-weight: 700; color: #f6f7fb; line-height: 1.12; }
  .report-subtitle { font-size: 0.95rem; color: var(--muted); margin: 0 0 0.5rem; font-family: 'Inter', sans-serif; }
  .report-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 0.55rem 3rem; max-width: 640px; margin: 2.25rem auto 0; text-align: left; font-family: 'Inter', sans-serif; }
  .report-meta div { display: flex; justify-content: space-between; align-items: center; gap: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }
  .report-meta dt { color: var(--muted); font-weight: 600; margin: 0; text-transform: uppercase; letter-spacing: 0.04em; font-size: 0.68rem; }
  .report-meta dd { margin: 0; color: #e7e8f0; font-weight: 600; text-align: right; font-size: 0.85rem; }
  .report-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.9rem; max-width: 640px; width: 100%; margin: 2.25rem auto 0; font-family: 'Inter', sans-serif; }
  .report-stat { display: flex; flex-direction: column; align-items: center; gap: 0.35rem; padding: 1.1rem 0.5rem; border: 1px solid var(--border); border-radius: 10px; background: #141a38; }
  .report-stat-value { font-size: 2rem; font-weight: 800; line-height: 1; }
  .report-stat-label { font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); text-align: center; }
  .report-stat.stat-neutral .report-stat-value { color: var(--accent); }
  .report-stat.stat-corroborated .report-stat-value { color: var(--pass); }
  .report-stat.stat-single .report-stat-value { color: var(--amber); }
  .report-stat.stat-contested .report-stat-value { color: var(--fail); }
  .report-toc-page { page-break-after: always; }

  .report-section { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem 1.6rem; margin: 1.4rem 0; page-break-inside: avoid; }
  .report-section > h2 { color: var(--accent); font-size: 1.4rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-bottom: 1rem; }
  .report-subsection { margin: 1.1rem 0; }
  .report-subsection > h3 { font-size: 1.05rem; margin-bottom: 0.5rem; color: #cdd3ea; }
  .report-lede { font-style: italic; color: var(--muted); margin-bottom: 1rem; }
  .report-summary { font-size: 1.05rem; line-height: 1.75; color: #eef0f7; margin-bottom: 0.75rem; white-space: pre-line; }
  .report-note { font-family: 'Inter', sans-serif; font-size: 0.8rem; color: var(--faint); margin: 0; }
  .report-coverage { max-width: 640px; margin: 1.25rem auto 0; text-align: left; border-left: 3px solid var(--warn); padding: 0.6rem 0.85rem; background: #2a1c0e; color: #f0c38e; border-radius: 6px; }
  .count { color: var(--muted); font-weight: 400; font-size: 0.9em; }

  .report-toc { padding-left: 1.5rem; font-family: 'Inter', sans-serif; }
  .report-toc li { margin: 0.25rem 0; }

  .report-table { width: 100%; border-collapse: collapse; font-family: 'Inter', sans-serif; font-size: 0.9rem; margin: 0.5rem 0; }
  .report-table th, .report-table td { padding: 0.55rem 0.75rem; text-align: left; vertical-align: top; }
  .report-table thead th { background: var(--panel-2); color: var(--accent); border-bottom: 2px solid var(--border); font-weight: 600; }
  .report-table tbody tr { border-bottom: 1px solid var(--row); }
  .report-table tbody tr:hover td { background: #1f285044; }

  .report-fact-list { list-style: none; padding: 0; }
  .report-fact-list > li { margin-bottom: 1rem; padding: 0.75rem 1rem; border-left: 3px solid var(--accent); background: #141a38; border-radius: 0 8px 8px 0; page-break-inside: avoid; }
  .fact-head { font-family: 'Inter', sans-serif; font-size: 0.9rem; display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; margin-bottom: 0.5rem; }
  .fact-head .subject, .fact-head .object { font-weight: 600; color: #e7e8f0; }
  .fact-head .pred { color: var(--muted); font-style: italic; }
  .status { font-size: 0.7rem; text-transform: uppercase; font-weight: 700; padding: 0.12rem 0.5rem; border-radius: 10px; letter-spacing: 0.04em; white-space: nowrap; display: inline-block; }
  .report-table td.nowrap { white-space: nowrap; }
  .report-table td.pred { color: var(--muted); font-style: italic; }
  .status-corroborated { background: #34d39922; color: var(--pass); border: 1px solid #34d39955; }
  .status-single-source { background: #fbbf2422; color: var(--amber); border: 1px solid #fbbf2455; }
  .status-contested { background: #f8717122; color: var(--fail); border: 1px solid #f8717155; }
  .fact-head .meta { color: var(--muted); font-size: 0.75rem; margin-left: auto; }

  .citations { list-style: none; padding-left: 1rem; margin-top: 0.5rem; }
  .citations li { margin: 0.5rem 0; padding-left: 0.75rem; border-left: 2px solid var(--border); }
  .citations blockquote { margin: 0; padding: 0; font-style: italic; color: #cdd3ea; }
  .cite-meta { font-size: 0.75rem; color: var(--muted); margin-top: 0.25rem; font-family: 'Inter', sans-serif; }
  .doc-title { font-weight: 500; }

  .matrix-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 0.8rem; }
  .matrix-column { border: 1px solid var(--border); border-radius: 8px; overflow: hidden; background: var(--panel-2); }
  .matrix-head { background: #0e1430; color: var(--accent); padding: 0.45rem 0.6rem; margin: 0; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
  .matrix-column ul { list-style: none; padding: 0; margin: 0; }
  .matrix-column li { padding: 0.4rem 0.5rem; border-bottom: 1px solid var(--row); font-family: 'Inter', sans-serif; font-size: 0.75rem; display: block; }
  .matrix-column li.tech-corroborated { border-left: 3px solid var(--pass); }
  .matrix-column li.tech-single-source { border-left: 3px solid var(--amber); }
  .matrix-column li.tech-contested { border-left: 3px solid var(--fail); }
  .tech-id { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: var(--faint); display: block; }
  .tech-name { font-weight: 500; display: block; color: #cdd3ea; }
  .tech-meta { font-size: 0.65rem; color: var(--faint); display: block; }

  .related-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; }
  .related-card { border: 1px solid var(--border); border-radius: 8px; padding: 0.85rem 1rem; background: var(--panel-2); }
  .related-card h3 { font-size: 0.9rem; margin: 0 0 0.5rem; color: var(--accent); }
  .related-card ul { list-style: disc; padding-left: 1.5rem; margin: 0; font-family: 'Inter', sans-serif; font-size: 0.85rem; color: #cdd3ea; }
  .related-card li { margin: 0.2rem 0; }
  .exploited { color: var(--muted); font-size: 0.8rem; }

  .ioc-list { list-style: none; padding: 0; }
  .ioc-list li { display: flex; align-items: center; gap: 0.5rem; padding: 0.25rem 0; font-size: 0.85rem; color: #cfe8ff; }
  .freshness { display: inline-block; width: 0.5rem; height: 0.5rem; border-radius: 50%; }
  .freshness-active { background: var(--pass); }
  .freshness-dormant { background: var(--amber); }
  .freshness-historical { background: var(--faint); }
  .freshness-unknown { background: #3a3c57; }
  .ioc-meta { color: var(--muted); font-size: 0.75rem; }

  .pill { display: inline-block; padding: 0.12rem 0.5rem; border-radius: 10px; background: #2a2c45; color: #cdd3ea; font-size: 0.75rem; font-family: 'Inter', sans-serif; }
  .pill-validated { background: #34d39922; color: var(--pass); border: 1px solid #00e67544; }
  .pill-failed { background: #f8717122; color: var(--fail); border: 1px solid #f8717144; }
  .pill-irrelevant { background: #2a2c45; color: var(--muted); }

  .report-footer { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.78rem; color: var(--faint); text-align: center; font-family: 'Inter', sans-serif; }

  @media print {
    .no-print, .app-chrome { display: none !important; }
    main { padding: 0 !important; }
    /* Full-bleed like the Cyllex report: no forced page margin (that was the white border),
       the dark field fills the whole sheet, content is inset by padding. print-color-adjust
       keeps the dark field (and drops the browser's header/footer when the margin is 0). */
    @page { size: A4; margin: 0; }
    html, body { background: #10152b !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .report-root { max-width: none; margin: 0; padding: 0; background: #10152b; }
    .report-cover { margin: 0; padding: 3cm 1.6cm; min-height: auto; break-after: page; }
    /* Flatten the section cards for print (no boxes to split across a break) and inset content
       from the page edge; sections flow instead of being pushed whole (which left dark gaps). */
    .report-section { background: transparent; border: none; border-radius: 0; margin: 0.8rem 0; padding: 0.3rem 1.6cm; break-inside: auto; }
    .report-section > h2 { margin-bottom: 0.55rem; }
    .report-fact-list > li, .matrix-column, .related-card { break-inside: avoid; }
    .report-footer { padding: 1rem 1.6cm; }
  }
`
