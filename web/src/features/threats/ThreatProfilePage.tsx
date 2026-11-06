import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useInvestigations, useThreat } from '../../api/hooks'
import type { Fact } from '../../api/types'
import { Card } from '../../components/Card'
import { ExecutiveSummaryCard } from '../../components/ExecutiveSummaryCard'
import { ConfidenceBar } from '../../components/badges'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'
import { useMediaQuery } from '../../lib/useMediaQuery'
import { AttackMatrix } from '../investigations/AttackMatrix'
import { CitationsPanel } from './CitationsPanel'
import { EnrichCard } from './EnrichCard'
import { ExportButtons } from './ExportButtons'
import { FactsTable, factKey } from './FactsTable'
import { IcdConfidencePanel } from './IcdConfidencePanel'
import { IdentityAttributesCard } from './IdentityAttributesCard'
import { LivePipelineCard } from './LivePipelineCard'
import { SigmaCard } from './SigmaCard'
import { ThreatSidebar, isThreatSectionId, type ThreatSectionId } from './ThreatSidebar'

const NARROW = '(max-width: 900px)'

/**
 * React Router reuses this element when only `:id` changes (the graph navigates between profiles that way),
 * so the per-threat state lives in a body keyed on `id`: a new threat starts without the old selection or filters.
 */
export function ThreatProfilePage({ graphSlot }: { graphSlot?: (id: string) => ReactNode }) {
  const { id = '' } = useParams()
  return <ThreatProfile key={id} id={id} graphSlot={graphSlot} />
}

const STATUS_TEXT: Record<string, string> = {
  corroborated: 'text-emerald-400',
  'single-source': 'text-yellow-400',
  contested: 'text-red-400',
}

export function groupFacts(facts: Fact[]) {
  const techniques: Fact[] = []
  const tools: Fact[] = []
  const malware: Fact[] = []
  const indicators: Fact[] = []
  const targets: Fact[] = []
  const attribution: Fact[] = []
  const cves: Fact[] = []
  const other: Fact[] = []
  for (const fact of facts) {
    if (fact.predicate === 'uses' && fact.object.stix_type === 'attack-pattern') techniques.push(fact)
    else if (fact.predicate === 'uses' && fact.object.stix_type === 'tool') tools.push(fact)
    else if (fact.predicate === 'uses' && fact.object.stix_type === 'malware') malware.push(fact)
    else if (fact.predicate === 'indicates') indicators.push(fact)
    else if (fact.predicate === 'targets') targets.push(fact)
    else if (fact.predicate === 'attributed-to' || fact.predicate === 'alias-of') attribution.push(fact)
    else if (fact.predicate === 'exploits' || fact.object.stix_type === 'vulnerability') cves.push(fact)
    else other.push(fact)
  }
  return { techniques, tools, malware, indicators, targets, attribution, cves, other }
}

/** The six-count strip of an entity: techniques, malware, tools, indicators, targets and vulnerabilities. */
/** Render actor-attribution chips in the profile header: sectors[] from the STIX 2.1-
 * correct `threat-actor.sectors` shape (0.13+), plus country from `identity` entities.
 * Returns null when nothing to show so the header stays clean on fresh actors. */
export function SectorChips({ attributes }: { attributes: Record<string, string | string[]> }) {
  const sectors = Array.isArray(attributes.sectors) ? attributes.sectors : []
  const country = typeof attributes.country === 'string' ? attributes.country : null
  // The legacy single-string sector key (0.11-era identity entities) renders as a chip too.
  const legacySector = typeof attributes.sector === 'string' ? attributes.sector : null
  if (sectors.length === 0 && !country && !legacySector) return null
  return (
    <div className="flex flex-wrap gap-2 mt-3" aria-label="Sector attribution">
      {sectors.map((sector) => (
        <span key={`sector-${sector}`} title="Observed sector target (attributes.sectors)"
          className="px-2 py-0.5 rounded text-xs bg-emerald-900/40 text-emerald-200 border border-emerald-700/40">
          sector: {sector}
        </span>
      ))}
      {legacySector && (
        <span title="Identity sector (legacy single-string attribute)"
          className="px-2 py-0.5 rounded text-xs bg-emerald-900/40 text-emerald-200 border border-emerald-700/40">
          sector: {legacySector}
        </span>
      )}
      {country && (
        <span title="Identity country" className="px-2 py-0.5 rounded text-xs bg-sky-900/40 text-sky-200 border border-sky-700/40">
          country: {country}
        </span>
      )}
    </div>
  )
}


export function FactCountStrip({ facts }: { facts: Fact[] }) {
  const groups = useMemo(() => groupFacts(facts), [facts])
  const overview: [string, number, string][] = [
    ['Techniques', groups.techniques.length, 'text-emerald-300'],
    ['Malware', groups.malware.length, 'text-red-300'],
    ['Tools', groups.tools.length, 'text-amber-300'],
    ['Indicators', groups.indicators.length, 'text-teal-300'],
    ['Targets & sectors', groups.targets.length, 'text-slate-300'],
    ['Vulnerabilities', groups.cves.length, 'text-rose-300'],
  ]
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      {overview.map(([label, count, tone]) => (
        <div key={label} className="card p-3">
          <div className="text-xs uppercase tracking-wide text-gray-400">{label}</div>
          <div className={`text-2xl font-semibold ${tone}`}>{count}</div>
        </div>
      ))}
    </div>
  )
}

/** How solid the evidence is, in one line: the status split of every fact on the profile.
 * This is what the collapsed "All facts" card says now — it used to hold a paragraph of
 * navigation instructions, which told the operator how to use the sidebar instead of
 * telling them anything about the threat. */
export function EvidenceStrength({ facts }: { facts: Fact[] }) {
  const counts = facts.reduce<Record<string, number>>((acc, fact) => {
    acc[fact.status] = (acc[fact.status] ?? 0) + 1
    return acc
  }, {})
  const parts: [string, string][] = [
    ['corroborated', 'corroborated by two or more independent sources'],
    ['single-source', 'asserted by one source only'],
    ['contested', 'sources disagree'],
  ]
  return (
    <ul className="space-y-1 text-sm">
      {parts.map(([status, explanation]) => (
        <li key={status} className="flex items-baseline gap-2">
          <span className={`font-mono tabular-nums font-semibold ${STATUS_TEXT[status] ?? 'text-gray-300'}`}>
            {counts[status] ?? 0}
          </span>
          <span className="text-gray-400">{explanation}</span>
        </li>
      ))}
    </ul>
  )
}

function ThreatProfile({ id, graphSlot }: { id: string; graphSlot?: (id: string) => ReactNode }) {
  const { data, error, isLoading } = useThreat(id)
  const [selected, setSelected] = useState<string | null>(null)
  const [showAllFacts, setShowAllFacts] = useState(false)
  const navigate = useNavigate()
  const { hash } = useLocation()
  const [searchParams, setSearchParams] = useSearchParams()
  const narrow = useMediaQuery(NARROW)
  const groups = useMemo(() => (data ? groupFacts(data.facts) : null), [data])
  const investigations = useInvestigations()
  const latestReportInvId = useMemo(() => {
    const mine = (investigations.data ?? [])
      .filter((inv) => inv.resolved_entity_id === id && inv.state === 'finished')
      .sort((a, b) => b.id - a.id)
    return mine[0]?.id ?? null
  }, [investigations.data, id])
  const loaded = !!data
  // Legacy deep-link: redirect old #generate-ttps anchors to the detection section.
  useEffect(() => {
    if (loaded && hash === '#generate-ttps') {
      setSearchParams((current) => {
        const params = new URLSearchParams(current)
        params.set('section', 'sigma')
        return params
      }, { replace: true })
      navigate({ hash: '' }, { replace: true })
    }
  }, [loaded, hash, navigate, setSearchParams])
  if (isLoading) return <Loading />
  if (error || !data || !groups) return <ErrorCard error={error} />
  const selectedFact = data.facts.find((f) => factKey(f) === selected) ?? null
  const openTechnique = (entityId: string) => {
    const found = data.facts.find((f) => f.object.id === entityId)
    setSelected(found ? factKey(found) : null)
  }
  const openEntity = (entityId: string) => navigate(`/threats/${encodeURIComponent(entityId)}`)
  const requested = searchParams.get('section')
  const section: ThreatSectionId = isThreatSectionId(requested) ? requested : 'overview'
  const selectSection = (next: ThreatSectionId) =>
    setSearchParams((current) => {
      const params = new URLSearchParams(current)
      params.set('section', next)
      return params
    })
  const isIdentity = data.entity.stix_type === 'identity'
  const badges: Partial<Record<ThreatSectionId, string | number | null>> = {
    matrix: groups.techniques.length || null,
  }

  const renderHeader = (
    <>
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold break-words">{data.entity.name}</h1>
          <p className="text-sm text-gray-400 break-words">
            {data.entity.stix_type}{data.entity.attack ? ' · MITRE ATT&CK' : ''}{data.entity.external_id ? ` · ${data.entity.external_id}` : ''}
          </p>
          {data.aliases.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-3">
              {data.aliases.map((alias) => (
                <span key={`${alias.origin}|${alias.alias}`} title={`alias origin: ${alias.origin}`}
                  className={`px-2 py-0.5 rounded text-xs ${alias.origin === 'document' ? 'bg-yellow-900/40 text-yellow-300' : 'bg-gray-700 text-gray-300'}`}>
                  {alias.alias}
                </span>
              ))}
            </div>
          )}
          <SectorChips attributes={data.entity.attributes ?? {}} />
        </div>
        <ExportButtons threatId={id} leading={<>
          {latestReportInvId !== null && (
            <Link to={`/investigations/${latestReportInvId}/report`}
              className="btn btn-secondary btn-sm"
              title="Open the printable dossier for this threat (consolidated findings)">
              Open dossier
            </Link>
          )}
          <Link to={`/threats/${encodeURIComponent(id)}/history`}
            className="btn btn-secondary btn-sm"
            title="See what has changed about this threat since the previous investigation">
            View history →
          </Link>
        </>} />
      </div>
      <FactCountStrip facts={data.facts} />
    </>
  )

  if (data.facts.length === 0) {
    return (
      <div className="space-y-6">
        {renderHeader}
        <Card><EmptyState>No facts yet. Investigate this threat to collect quote-backed facts.</EmptyState></Card>
        {graphSlot?.(id)}
      </div>
    )
  }

  const sectionContent = (() => {
    switch (section) {
      case 'overview':
        return (
          <div className="space-y-6">
            <ExecutiveSummaryCard threatId={id} />
            <Card title={`All facts (${data.facts.length})`}
              actions={
                <button type="button" className="btn btn-secondary btn-sm" onClick={() => setShowAllFacts(!showAllFacts)}>
                  {showAllFacts ? 'Hide' : 'Show table'}
                </button>
              }>
              {showAllFacts ? (
                <FactsTable facts={data.facts} entityId={data.entity.id} selected={selected} onSelect={setSelected} />
              ) : (
                <EvidenceStrength facts={data.facts} />
              )}
            </Card>
            {graphSlot?.(id)}
          </div>
        )
      case 'matrix':
        return (
          <div className="space-y-6">
            {data.attack_matrix && groups.techniques.length > 0 && (
              <Card title="ATT&CK matrix"
                actions={<span className="text-xs text-gray-400">{groups.techniques.length} technique{groups.techniques.length === 1 ? '' : 's'}</span>}>
                <AttackMatrix tactics={data.attack_matrix.tactics} onSelect={openTechnique} />
              </Card>
            )}
            {groups.indicators.length > 0 && (
              <Card title="Indicators of compromise"
                actions={<span className="text-xs text-gray-400">{groups.indicators.length}</span>}>
                <FactList facts={groups.indicators} selected={selected} onSelect={setSelected} onOpen={openEntity} />
              </Card>
            )}
            {(groups.malware.length + groups.tools.length) > 0 && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {groups.malware.length > 0 && (
                  <Card title="Malware" actions={<span className="text-xs text-gray-400">{groups.malware.length}</span>}>
                    <FactList facts={groups.malware} selected={selected} onSelect={setSelected} onOpen={openEntity} />
                  </Card>
                )}
                {groups.tools.length > 0 && (
                  <Card title="Tools" actions={<span className="text-xs text-gray-400">{groups.tools.length}</span>}>
                    <FactList facts={groups.tools} selected={selected} onSelect={setSelected} onOpen={openEntity} />
                  </Card>
                )}
              </div>
            )}
            {(groups.targets.length + groups.cves.length + groups.attribution.length) > 0 && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {groups.targets.length > 0 && (
                  <Card title="Targets & sectors" actions={<span className="text-xs text-gray-400">{groups.targets.length}</span>}>
                    <FactList facts={groups.targets} selected={selected} onSelect={setSelected} onOpen={openEntity} />
                  </Card>
                )}
                {groups.cves.length > 0 && (
                  <Card title="Vulnerabilities exploited" actions={<span className="text-xs text-gray-400">{groups.cves.length}</span>}>
                    <FactList facts={groups.cves} selected={selected} onSelect={setSelected} onOpen={openEntity} />
                  </Card>
                )}
                {groups.attribution.length > 0 && (
                  <Card title="Attribution & aliases" actions={<span className="text-xs text-gray-400">{groups.attribution.length}</span>}>
                    <FactList facts={groups.attribution} selected={selected} onSelect={setSelected} onOpen={openEntity} />
                  </Card>
                )}
              </div>
            )}
          </div>
        )
      case 'graph':
        return graphSlot?.(id) ?? <Card title="Relationship graph"><EmptyState>Graph not available.</EmptyState></Card>
      case 'latest-run':
        return <LatestInvestigationLiveTree entityId={id} entityName={data.entity.name} />
      case 'sigma':
        return <SigmaCard entityId={id} />
      case 'enrich':
        return <EnrichCard />
      case 'identity':
        return isIdentity
          ? <IdentityAttributesCard entityId={data.entity.id} attributes={data.entity.attributes ?? {}} />
          : <Card title="Identity attributes"><EmptyState>This entity is not an identity.</EmptyState></Card>
    }
  })()

  // CitationsPanel + IcdConfidencePanel always render on overview + matrix (even with no fact
  // selected: they show their own "Select a fact..." empty state). Elsewhere they would eat
  // width without adding anything, so we hide them.
  const showCitations = section === 'matrix' || section === 'overview'

  return (
    <div className="space-y-6">
      {renderHeader}
      <div className={narrow ? 'space-y-4' : 'flex items-start gap-6'}>
        <ThreatSidebar active={section} onSelect={selectSection} badges={badges} narrow={narrow} isIdentity={isIdentity} />
        <div className="min-w-0 flex-1 space-y-6">
          {showCitations ? (
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
              <div className="xl:col-span-2 space-y-6">{sectionContent}</div>
              <div className="xl:col-span-1">
                <div className="xl:sticky xl:top-6 space-y-6">
                  <CitationsPanel fact={selectedFact} />
                  <IcdConfidencePanel fact={selectedFact} threatId={id} />
                </div>
              </div>
            </div>
          ) : sectionContent}
        </div>
      </div>
    </div>
  )
}

/** Compact fact row: primary label, status color, meta, "open" affordance. */
/**
 * Resolve the investigation attached to this entity so the LivePipelineCard knows what to
 * poll. Order of preference:
 *   1. A running/paused investigation whose `resolved_entity_id` matches — the Analyst
 *      resolved the actor and the ID link is authoritative.
 *   2. A running/paused investigation whose `target` string matches the entity's
 *      canonical name case-insensitively — the EARLY STAGE fallback. During the first
 *      few minutes of a run the Analyst has not resolved the entity yet and
 *      `resolved_entity_id` is still NULL, but the operator typed the target into
 *      `argus investigate`, so a string match is a safe second-best.
 *   3. The newest finished investigation of either shape, so the card renders a resting
 *      snapshot once the run is done.
 *   4. null — no investigation ever targeted this entity, so the card does not mount.
 */
function LatestInvestigationLiveTree({ entityId, entityName }: { entityId: string; entityName: string }) {
  const { data } = useInvestigations()
  const investigation = useMemo(() => {
    const all = data ?? []
    const nameMatch = (inv: typeof all[number]) =>
      inv.target.trim().toLowerCase() === entityName.trim().toLowerCase()
    const idMatch = (inv: typeof all[number]) => inv.resolved_entity_id === entityId
    const live = (inv: typeof all[number]) => inv.state === 'running' || inv.state === 'paused'
    const forEntity = all.filter((inv) => idMatch(inv) || nameMatch(inv))
    if (forEntity.length === 0) return null
    return forEntity.find((inv) => live(inv) && idMatch(inv))
        ?? forEntity.find(live)
        ?? forEntity[0]
  }, [data, entityId, entityName])
  if (investigation === null) return null
  return <LivePipelineCard investigationId={investigation.id} />
}


function FactList({ facts, selected, onSelect, onOpen }: {
  facts: Fact[]
  selected: string | null
  onSelect: (key: string) => void
  onOpen: (entityId: string) => void
}) {
  const sorted = [...facts].sort((a, b) => {
    const rank = (status: string) => (status === 'corroborated' ? 0 : status === 'single-source' ? 1 : 2)
    return rank(a.status) - rank(b.status) || b.confidence - a.confidence || a.object.label.localeCompare(b.object.label)
  })
  return (
    <ul className="space-y-1 max-h-96 overflow-y-auto pr-1">
      {sorted.map((fact) => {
        const key = factKey(fact)
        const isSelected = key === selected
        const seenRange = fact.first_seen && fact.last_seen && fact.first_seen !== fact.last_seen
          ? `${fact.first_seen} → ${fact.last_seen}` : (fact.last_seen ?? fact.first_seen ?? null)
        return (
          <li key={key}>
            <button type="button" onClick={() => onSelect(key)}
              className={`w-full text-left px-3 py-2 rounded border ${isSelected ? 'border-purple-500 bg-purple-900/20' : 'border-gray-700 hover:border-gray-600 hover:bg-gray-800/60'} focus:outline-none focus-visible:ring-2 focus-visible:ring-gray-400`}>
              <div className="flex items-center gap-2">
                <span className={`text-sm font-mono truncate ${STATUS_TEXT[fact.status] ?? 'text-gray-300'}`}>
                  {fact.object.label}
                </span>
                {fact.object.external_id && fact.object.stix_type === 'vulnerability' && (
                  <span className="text-xs text-gray-500">{fact.object.external_id}</span>
                )}
              </div>
              <div className="flex items-center gap-2 mt-1 text-xs text-gray-500">
                <ConfidenceBar value={fact.confidence} />
                <span>{fact.admiralty}</span>
                <span>· {fact.source_count} src</span>
                {seenRange && <span>· {seenRange}</span>}
                <span className="ml-auto">
                  <button type="button" onClick={(event) => { event.stopPropagation(); onOpen(fact.object.id) }}
                    className="text-purple-400 hover:underline text-xs" aria-label={`Open ${fact.object.label}`}>
                    open →
                  </button>
                </span>
              </div>
            </button>
          </li>
        )
      })}
    </ul>
  )
}
