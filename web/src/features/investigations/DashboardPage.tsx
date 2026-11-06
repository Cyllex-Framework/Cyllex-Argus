import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useActiveJob, useCampaigns, useGraph, useInvestigationDashboard, useRefreshWhenJobsEnd, useThreat, useTrace } from '../../api/hooks'
import type { DashboardEntity, Tactic, Scope, ScopeParam } from '../../api/types'
import { Card } from '../../components/Card'
import { ScopeSwitch } from '../../components/ScopeSwitch'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'
import { SetupNotice, useMissingPrerequisites } from '../../components/SetupNotice'
import { CitationsPanel } from '../threats/CitationsPanel'
import { FactsTable, factKey } from '../threats/FactsTable'
import { LivePipelineCard } from '../threats/LivePipelineCard'
import { ThreatGraph } from '../threats/ThreatGraph'
import { ThreatGraphFullscreen } from '../threats/ThreatGraphFullscreen'
import { AttackMatrix } from './AttackMatrix'
import { EntityDetailPanel } from './EntityDetailPanel'
import { concerns } from './InvestigationDetailPage'
import { InvestigationHeader } from './InvestigationHeader'
import { PipelineTrace } from './PipelineTrace'
import { useMediaQuery } from '../../lib/useMediaQuery'
import { DashboardCampaigns } from './DashboardCampaigns'
import { DashboardDocuments } from './DashboardDocuments'
import { DashboardOverview } from './DashboardOverview'
import { DashboardSidebar, isSectionId, type SectionId } from './DashboardSidebar'
import { InvestigationQuickActions } from './InvestigationQuickActions'

const INVESTIGATION_JOBS = ['investigate', 'resume'] as const
const ATTACK_ONLY = ['attack'] as const
const NARROW = '(max-width: 900px)'

const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`

/** The router reuses this element when only `:id` changes, so the page state lives in a body keyed on `id`. */
export function DashboardPage() {
  const { id = '' } = useParams()
  return <Dashboard key={id} id={id} />
}

function Dashboard({ id }: { id: string }) {
  const [searchParams, setSearchParams] = useSearchParams()
  const scope: Scope = searchParams.get('scope') === 'investigation' ? 'investigation' : 'everything'
  const scopeParam: ScopeParam | undefined = scope === 'investigation' ? `investigation:${id}` : undefined
  const setScope = (next: Scope) =>
    setSearchParams((current) => {
      const params = new URLSearchParams(current)
      if (next === 'investigation') params.set('scope', 'investigation')
      else params.delete('scope')
      return params
    })
  const { data, error, isLoading } = useInvestigationDashboard(id, scopeParam)
  // A job that ends refreshes every query, so the dashboard fills in with what the job just wrote.
  useRefreshWhenJobsEnd()
  const runningJobId = useActiveJob(INVESTIGATION_JOBS, {
    latest: false,
    matches: (job) => !!data && concerns(job, data.investigation),
  })
  const attackMissing = useMissingPrerequisites(ATTACK_ONLY).length > 0
  const narrow = useMediaQuery(NARROW)
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null)
  const [isFullscreen, setIsFullscreen] = useState(false)

  if (isLoading) return <Loading />
  if (error || !data) {
    return (
      <div className="space-y-4">
        <ErrorCard error={error} />
        <Link to="/investigations" className="text-sm text-purple-400 hover:underline">Back to investigations</Link>
      </div>
    )
  }
  const { investigation, entity, attack_matrix: matrix } = data
  const live = investigation.state === 'running'
  const emptyContribution = scope === 'investigation' && entity !== null && matrix.tactics.every((tactic) => tactic.techniques.length === 0)
  const documents = Object.values(investigation.counts).reduce((sum, count) => sum + count, 0)

  const techniques = countTechniques(matrix.tactics)
  const defaultSection: SectionId = !live && entity && techniques > 0 ? 'matrix' : 'overview'
  const requested = searchParams.get('section')
  const section: SectionId = isSectionId(requested) ? requested : defaultSection
  const selectSection = (next: SectionId) =>
    setSearchParams((current) => {
      const params = new URLSearchParams(current)
      params.set('section', next)
      return params
    })
  const liveMark = live ? <span className="text-xs text-yellow-400">updating live</span> : undefined
  const badges = {
    matrix: `${plural(matrix.tactics.length, 'tactic')} · ${plural(techniques, 'technique')}`,
    graph: entity ? <GraphBadge entityId={entity.id} scope={scopeParam} /> : undefined,
    campaigns: entity ? <CampaignsBadge entityId={entity.id} scope={scopeParam} /> : undefined,
    facts: entity ? <FactsBadge entityId={entity.id} scope={scopeParam} /> : undefined,
    trace: <TraceBadge id={id} />,
    documents: documents,
  }

  return (
    <div className="space-y-6">
      <InvestigationHeader investigation={investigation} entity={entity} runningJobId={runningJobId}
        techniques={techniques} scope={scopeParam} />
      <ScopeSwitch value={scope} onChange={setScope} investigationEmpty={emptyContribution} />
      <div className={narrow ? 'space-y-4' : 'flex items-start gap-6'}>
        <DashboardSidebar active={section} onSelect={selectSection} badges={badges} narrow={narrow} investigation={investigation} entity={entity} />
        <div className="min-w-0 flex-1 space-y-6">
          {section === 'overview' && (
            <>
              <InvestigationQuickActions investigation={investigation} entity={entity} />
              <LivePipelineCard investigationId={investigation.id} />
              <DashboardOverview investigation={investigation} entity={entity} scope={scopeParam} attackMissing={attackMissing} />
            </>
          )}
          {section === 'matrix' && (
            <Card title="ATT&CK matrix" actions={liveMark}>
              {attackMissing ? (
                <SetupNotice needs={ATTACK_ONLY} purpose="show the ATT&CK matrix" />
              ) : (
                <>
                  {!entity && (
                    <p className="mb-3 text-sm text-gray-400">
                      {investigation.state === 'running'
                        ? 'Resolving target…'
                        : 'Target not resolved — the matrix is empty.'}
                    </p>
                  )}
                  <AttackMatrix tactics={matrix.tactics} scope={scopeParam} />
                </>
              )}
            </Card>
          )}
          {section === 'graph' && (entity ? (
            <GraphSection entity={entity} scope={scopeParam} live={live} onSelect={setSelectedEntityId} onExpand={() => setIsFullscreen(true)} />
          ) : (
            <Card title="Relationship graph">
              <EmptyState>Waiting for a resolved target.</EmptyState>
            </Card>
          ))}
          {section === 'campaigns' && (
            <DashboardCampaigns entityId={entity?.id ?? null} scope={scopeParam} />
          )}
          {section === 'facts' && (entity ? (
            <FactsSection entity={entity} scope={scopeParam} live={live} />
          ) : (
            <Card title="Facts">
              <EmptyState>Waiting for a resolved target.</EmptyState>
            </Card>
          ))}
          {section === 'trace' && <PipelineTrace investigationId={id} />}
          {section === 'documents' && <DashboardDocuments investigationId={id} />}
        </div>
      </div>
      {entity && isFullscreen && (
        <ThreatGraphFullscreen id={entity.id} scope={scopeParam} onClearScope={() => setScope('everything')} onClose={() => setIsFullscreen(false)} onSelect={setSelectedEntityId}
          isPanelOpen={selectedEntityId !== null} />
      )}
      <EntityDetailPanel entityId={selectedEntityId} scope={scopeParam} onClose={() => setSelectedEntityId(null)} />
    </div>
  )
}

const countTechniques = (tactics: Tactic[]) => tactics.reduce((sum, tactic) => sum + tactic.techniques.length, 0)

function GraphBadge({ entityId, scope }: { entityId: string; scope?: ScopeParam }) {
  const { data } = useGraph(entityId, 1, undefined, scope)
  return data ? `${plural(data.nodes.length, 'node')} · ${plural(data.edges.length, 'edge')}` : null
}

function CampaignsBadge({ entityId, scope }: { entityId: string; scope?: ScopeParam }) {
  const { data } = useCampaigns(entityId, scope)
  return data ? data.campaigns.length : null
}

function FactsBadge({ entityId, scope }: { entityId: string; scope?: ScopeParam }) {
  const { data } = useThreat(entityId, scope)
  return data ? data.facts.length : null
}

function TraceBadge({ id }: { id: string }) {
  const { data } = useTrace(id)
  return data ? data.events.length : null
}

function GraphSection({ entity, scope, live, onSelect, onExpand }: {
  entity: DashboardEntity
  scope?: ScopeParam
  live: boolean
  onSelect: (id: string) => void
  onExpand: () => void
}) {
  const { data, error, isLoading } = useGraph(entity.id, 1, undefined, scope)
  return (
    <Card title="Relationship graph" actions={live ? <span className="text-xs text-yellow-400">updating live</span> : undefined}>
      {isLoading ? <Loading /> : error || !data ? <ErrorCard error={error} /> : data.nodes.length === 0 ? (
        <EmptyState>No relationships yet.</EmptyState>
      ) : (
        <ThreatGraph graph={data} rootId={entity.id} mode="embedded" tall onSelect={onSelect} onExpand={onExpand} />
      )}
    </Card>
  )
}

function FactsSection({ entity, scope, live }: { entity: DashboardEntity; scope?: ScopeParam; live: boolean }) {
  const { data, error, isLoading } = useThreat(entity.id, scope)
  const [selected, setSelected] = useState<string | null>(null)
  const selectedFact = data?.facts.find((fact) => factKey(fact) === selected) ?? null
  return (
    <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
      <Card title="Facts" className="xl:col-span-2 min-w-0" actions={live ? <span className="text-xs text-yellow-400">updating live</span> : undefined}>
        {isLoading ? <Loading /> : error || !data ? <ErrorCard error={error} /> : data.facts.length === 0 ? (
          <EmptyState>No facts yet.</EmptyState>
        ) : (
          <FactsTable facts={data.facts} entityId={entity.id} selected={selected} onSelect={setSelected} />
        )}
      </Card>
      <CitationsPanel fact={selectedFact} />
    </div>
  )
}
