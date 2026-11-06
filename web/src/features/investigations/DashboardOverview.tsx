import { useThreat } from '../../api/hooks'
import type { DashboardEntity, DashboardInvestigation, ScopeParam } from '../../api/types'
import { Card } from '../../components/Card'
import { ExecutiveSummaryCard } from '../../components/ExecutiveSummaryCard'
import { SetupNotice } from '../../components/SetupNotice'
import { FactCountStrip } from '../threats/ThreatProfilePage'

/**
 * The Overview section: the verdict first, then the counts that back it.
 *
 * It used to open with an "Overview" card repeating the entity's type and alias chips — which
 * the page header and the sidebar header already show, so the operator read the same identity
 * three times before reaching a single fact. That card is gone; identity belongs to the header
 * alone, and this section now answers "what did we learn?" instead.
 */
export function DashboardOverview({ investigation, entity, scope, attackMissing }: {
  investigation: DashboardInvestigation
  entity: DashboardEntity | null
  scope?: ScopeParam
  attackMissing: boolean
}) {
  return (
    <div className="space-y-6">
      {attackMissing && <SetupNotice needs={['attack']} purpose="show the ATT&CK matrix" />}
      {entity ? (
        <>
          <ExecutiveSummaryCard threatId={entity.id} />
          <EntityCounts entityId={entity.id} scope={scope} />
        </>
      ) : (
        <Card title="Target">
          <p className="text-sm text-gray-400">
            {investigation.state === 'running'
              ? <>Resolving <span className="font-mono">{investigation.target}</span> against the knowledge base — the summary appears once the run attributes it to an actor.</>
              : <>This run never resolved <span className="font-mono">{investigation.target}</span> to a single actor, so there is no profile to summarize. The documents and pipeline trace below still show what it collected.</>}
          </p>
        </Card>
      )}
    </div>
  )
}

function EntityCounts({ entityId, scope }: { entityId: string; scope?: ScopeParam }) {
  const { data } = useThreat(entityId, scope)
  return data ? <FactCountStrip facts={data.facts} /> : null
}
