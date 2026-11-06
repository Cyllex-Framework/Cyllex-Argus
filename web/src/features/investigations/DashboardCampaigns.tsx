import { useState } from 'react'
import { useCampaigns } from '../../api/hooks'
import type { Campaign, ScopeParam } from '../../api/types'
import { Card } from '../../components/Card'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'
import { formatDate } from '../../lib/format'
import { CampaignGraphModal } from './CampaignGraphModal'

/**
 * Lists the campaigns Argus has linked to the investigation's target entity. Click a card to open the
 * campaign's kill-chain graph in a centered modal, showing the techniques it used in ATT&CK phase order.
 */
export function DashboardCampaigns({ entityId, scope }: { entityId: string | null; scope?: ScopeParam }) {
  const { data, error, isLoading } = useCampaigns(entityId, scope)
  const [open, setOpen] = useState<Campaign | null>(null)

  if (!entityId) {
    return (
      <Card title="Known campaigns">
        <EmptyState>Waiting for a resolved target.</EmptyState>
      </Card>
    )
  }
  if (isLoading) return <Card title="Known campaigns"><Loading /></Card>
  if (error || !data) return <Card title="Known campaigns"><ErrorCard error={error} /></Card>
  const { campaigns } = data

  return (
    <Card title="Known campaigns">
      {campaigns.length === 0 ? (
        <EmptyState>
          No campaigns linked to this entity yet. A campaign appears here as soon as Argus records a fact
          tying the entity to it (<code>attributed-to</code>, <code>uses</code> and the like).
        </EmptyState>
      ) : (
        <ul className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {campaigns.map((campaign) => (
            <li key={campaign.id}>
              <button type="button" onClick={() => setOpen(campaign)}
                className="group w-full text-left border border-gray-800 bg-gray-800/30 hover:border-gray-600 hover:bg-gray-800/60 rounded p-4 transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-white/40">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-gray-100 truncate" title={campaign.name}>
                      {campaign.name}
                    </div>
                    {campaign.external_id && (
                      <div className="text-xs text-gray-500 font-mono mt-0.5">{campaign.external_id}</div>
                    )}
                  </div>
                  <span className="shrink-0 text-[10px] font-mono text-purple-300 bg-purple-900/40 border border-purple-800 rounded px-1.5 py-0.5 whitespace-nowrap">
                    {campaign.techniques} TTP{campaign.techniques === 1 ? '' : 's'}
                  </span>
                </div>
                <div className="mt-3 text-[11px] text-gray-500 flex items-center gap-3 flex-wrap">
                  <span>{campaign.first_seen ? formatDate(campaign.first_seen) : 'undated'}
                    {campaign.last_seen && campaign.last_seen !== campaign.first_seen && (
                      <> → {formatDate(campaign.last_seen)}</>
                    )}
                  </span>
                  <span className="text-purple-400 group-hover:underline ml-auto">Open graph →</span>
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}
      {open && <CampaignGraphModal campaign={open} scope={scope} onClose={() => setOpen(null)} />}
    </Card>
  )
}
