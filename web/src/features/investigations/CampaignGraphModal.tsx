import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useCampaignMatrix, useGraph } from '../../api/hooks'
import type { Campaign, ScopeParam } from '../../api/types'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'
import { formatDate } from '../../lib/format'
import { ThreatGraph } from '../threats/ThreatGraph'
import { AttackMatrix } from './AttackMatrix'
import { TechniqueModal } from './TechniqueModal'

type Tab = 'graph' | 'matrix'

/**
 * Centered modal showing a campaign's details in two tabs: `Graph` (kill-chain layout of its TTPs
 * through the attributed actor) and `Matrix` (ATT&CK matrix filtered to the campaign's techniques,
 * same visuals as the main dashboard matrix). Clicking a technique in either tab opens the
 * TechniqueModal with the citations.
 */
export function CampaignGraphModal({ campaign, scope, onClose }: {
  campaign: Campaign
  scope?: ScopeParam
  onClose: () => void
}) {
  const closeButton = useRef<HTMLButtonElement>(null)
  const [tab, setTab] = useState<Tab>('graph')
  const graph = useGraph(campaign.id, 2, 200, scope)
  const matrix = useCampaignMatrix(campaign.id)
  const [technique, setTechnique] = useState<{ id: string; tactic: string } | null>(null)

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    closeButton.current?.focus()
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return createPortal(
    <>
      <div data-testid="campaign-modal-backdrop" className="fixed inset-0 z-50 bg-black/60" onClick={onClose} aria-hidden="true" />
      <div role="dialog" aria-modal="true" aria-label={`Campaign ${campaign.name}`}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
        {/* h-[90vh] not max-h: a definite height is what lets the flex-1 body give the graph room to render. */}
        <div className="pointer-events-auto bg-gray-900 border border-gray-700 rounded-lg shadow-2xl w-full max-w-5xl h-[90vh] flex flex-col">
          {/* HEADER */}
          <div className="flex items-start justify-between gap-3 p-5 pb-3 border-b border-gray-800">
            <div className="min-w-0">
              <h2 className="text-lg font-semibold text-gray-100 break-words leading-tight">{campaign.name}</h2>
              <p className="mt-1 text-xs text-gray-400 flex items-center gap-3 flex-wrap">
                {campaign.external_id && <span className="font-mono">{campaign.external_id}</span>}
                <span>
                  {campaign.first_seen ? formatDate(campaign.first_seen) : 'undated'}
                  {campaign.last_seen && campaign.last_seen !== campaign.first_seen && (
                    <> → {formatDate(campaign.last_seen)}</>
                  )}
                </span>
                <span>
                  {campaign.techniques} technique{campaign.techniques === 1 ? '' : 's'} observed
                </span>
              </p>
            </div>
            <button ref={closeButton} type="button" aria-label="Close"
              className="shrink-0 text-gray-400 hover:text-gray-100 text-2xl leading-none p-1"
              onClick={onClose}>
              ×
            </button>
          </div>

          {/* TAB BAR */}
          <div role="tablist" aria-label="Campaign view" className="flex gap-1 px-5 border-b border-gray-800">
            {(['graph', 'matrix'] as const).map((candidate) => {
              const isActive = tab === candidate
              const label = candidate === 'graph' ? 'Graph' : 'Campaign matrix'
              return (
                <button key={candidate} type="button" role="tab" aria-selected={isActive}
                  onClick={() => setTab(candidate)}
                  className={`px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${
                    isActive
                      ? 'border-white text-white font-semibold'
                      : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-600'
                  }`}>
                  {label}
                </button>
              )
            })}
          </div>

          {/* BODY */}
          <div role="tabpanel" aria-label={tab === 'graph' ? 'Graph' : 'Campaign matrix'}
            className="flex-1 min-h-0 p-4 overflow-auto">
            {tab === 'graph' && (
              graph.isLoading ? <Loading />
              : graph.error ? <ErrorCard error={graph.error} />
              : !graph.data || graph.data.edges.length === 0 ? (
                <EmptyState>No linked entities to draw yet.</EmptyState>
              ) : (
                <div className="h-full">
                  <ThreatGraph graph={graph.data} rootId={campaign.id} mode="fullscreen"
                    layout="kill-chain" onSelect={(nodeId) => {
                      const node = graph.data!.nodes.find((n) => n.id === nodeId)
                      if (node?.type === 'attack-pattern') {
                        setTechnique({ id: nodeId, tactic: node.tactic ?? '' })
                      }
                    }} />
                </div>
              )
            )}
            {tab === 'matrix' && (
              matrix.isLoading ? <Loading />
              : matrix.error ? <ErrorCard error={matrix.error} />
              : !matrix.data || matrix.data.tactics.every((t) => t.techniques.length === 0) ? (
                <EmptyState>
                  No techniques recorded for this campaign yet. Direct <code>uses</code> edges on a
                  campaign are rare; the matrix also includes techniques reachable through its
                  attributed actor.
                </EmptyState>
              ) : (
                <AttackMatrix tactics={matrix.data.tactics} scope={scope} />
              )
            )}
          </div>

          {/* FOOTER / LEGEND */}
          <div className="px-5 py-2.5 border-t border-gray-800 text-[11px] text-gray-500">
            {tab === 'graph'
              ? 'Techniques are laid out in ATT&CK kill-chain order left to right. Edges carry the predicate (uses, attributed-to, …).'
              : 'Techniques come from the campaign\'s own uses edges plus the attributed actor\'s. Click a cell for its citations.'}
          </div>
        </div>
      </div>
      {technique && (
        <TechniqueModal entityId={technique.id} tacticName={technique.tactic} scope={scope}
          onClose={() => setTechnique(null)} />
      )}
    </>,
    document.body,
  )
}
