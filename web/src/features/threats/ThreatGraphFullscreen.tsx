import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import type cytoscape from 'cytoscape'
import { useGraph } from '../../api/hooks'
import type { ScopeParam } from '../../api/types'
import { ErrorCard, Loading } from '../../components/QueryState'
import { GRAPH_LAYOUT, type GraphLayout, ThreatGraph } from './ThreatGraph'
import { TYPE_LABEL } from './graphModel'
import { killChainPositions } from './killChainLayout'

export const FULLSCREEN_DEPTH = 3
export const FULLSCREEN_LIMIT = 200

/** BloodHound-style view centred on the APT: left drawer of filters, top bar of controls, search on top. */
/** `isPanelOpen`: another layer (the entity panel) is on top and owns Escape. */
export function ThreatGraphFullscreen({ id, onClose, onSelect, isPanelOpen = false, scope, onClearScope }: {
  id: string
  scope?: ScopeParam
  onClose: () => void
  onSelect: (id: string) => void
  isPanelOpen?: boolean
  /** Called when the user asks to leave the scoped view (empty-state button). */
  onClearScope?: () => void
}) {
  const { data, error, isLoading } = useGraph(id, FULLSCREEN_DEPTH, FULLSCREEN_LIMIT, scope)
  const [cy, setCy] = useState<cytoscape.Core | null>(null)
  const [hidden, setHidden] = useState<ReadonlySet<string>>(new Set())
  const [layout, setLayout] = useState<GraphLayout>('kill-chain')
  const [query, setQuery] = useState('')
  const [drawerOpen, setDrawerOpen] = useState(true)
  const closeButton = useRef<HTMLButtonElement>(null)

  const typeCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const node of data?.nodes ?? []) counts.set(node.type, (counts.get(node.type) ?? 0) + 1)
    return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b))
  }, [data])

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !isPanelOpen) onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose, isPanelOpen])
  useEffect(() => closeButton.current?.focus(), [])

  // Filters hide by display, not by rebuilding the elements: cheaper, and the layout is preserved.
  useEffect(() => {
    if (!cy) return
    cy.nodes().forEach((node) => {
      node.style('display', hidden.has(String(node.data('type'))) ? 'none' : 'element')
    })
  }, [cy, hidden])

  // Search dims nodes whose label doesn't match, so the interesting ones pop.
  useEffect(() => {
    if (!cy) return
    const needle = query.trim().toLowerCase()
    cy.nodes().forEach((node) => {
      const label = String(node.data('label') ?? '').toLowerCase()
      node.style('opacity', !needle || label.includes(needle) ? 1 : 0.15)
    })
    // Edges are dimmed when a search is on; not every cytoscape mock stubs `.edges()`.
    if (typeof cy.edges === 'function') {
      cy.edges().forEach((edge) => { edge.style('opacity', !needle ? 1 : 0.15) })
    }
  }, [cy, query])

  const toggle = (type: string) =>
    setHidden((current) => {
      const next = new Set(current)
      if (!next.delete(type)) next.add(type)
      return next
    })
  const fit = () => {
    if (!cy || !data) return
    if (layout === 'kill-chain') {
      cy.layout({ name: 'preset', positions: killChainPositions(data, id).positions, fit: true, padding: 60 }).run()
    } else {
      cy.layout({ ...GRAPH_LAYOUT, fit: true }).run()
    }
  }
  const focusRoot = () => {
    if (!cy) return
    const root = cy.$id(id)
    if (root.length) cy.animate({ center: { eles: root }, zoom: 1.2, duration: 250 })
  }
  const onReady = useCallback((instance: cytoscape.Core | null) => setCy(instance), [])

  return createPortal(
    <div role="dialog" aria-modal="true" aria-label="Relationship graph" className="fixed inset-0 z-50 bg-gray-900/95 flex flex-col">
      {/* Top bar: layout + Fit + Focus + Close */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-700 bg-gray-800/60 shrink-0">
        <button type="button" aria-label={drawerOpen ? 'Hide filters' : 'Show filters'}
          className="btn btn-secondary btn-sm" onClick={() => setDrawerOpen(!drawerOpen)}>
          {drawerOpen ? '‹ Filters' : 'Filters ›'}
        </button>
        <div className="btn-group">
          <button type="button" aria-pressed={layout === 'kill-chain'} onClick={() => setLayout('kill-chain')}
            className={`btn btn-sm ${layout === 'kill-chain' ? 'active' : ''}`} title="Techniques laid out by MITRE tactic">
            Kill chain
          </button>
          <button type="button" aria-pressed={layout === 'force'} onClick={() => setLayout('force')}
            className={`btn btn-sm ${layout === 'force' ? 'active' : ''}`} title="Force-directed layout">
            Force
          </button>
        </div>
        <input type="search" value={query} onChange={(event) => setQuery(event.target.value)}
          placeholder="Search node…" aria-label="Search graph"
          className="input input-sm flex-1 max-w-md" />
        {scope && (
          <span className="text-xs px-2 py-1 rounded bg-purple-900/40 text-purple-300 border border-purple-800" title="Toggle it back on the dashboard">
            Scope: This investigation
          </span>
        )}
        {data?.truncated && (
          <span role="status" className="text-xs text-yellow-400">
            Showing {FULLSCREEN_LIMIT} relationships. Narrow the view with filters or search.
          </span>
        )}
        <div className="ml-auto flex gap-2">
          <button type="button" className="btn btn-secondary btn-sm" onClick={focusRoot}>Focus APT</button>
          <button type="button" className="btn btn-secondary btn-sm" onClick={fit}>Fit</button>
          <button ref={closeButton} type="button" className="btn btn-secondary btn-sm" onClick={onClose}>Close</button>
        </div>
      </div>

      <div className="flex-1 min-h-0 flex">
        {/* Left drawer: filter checkboxes per node type. */}
        {drawerOpen && (
          <aside className="w-56 shrink-0 border-r border-gray-700 bg-gray-800/40 p-3 overflow-y-auto">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400 mb-3">Node types</h3>
            <ul className="space-y-2">
              {typeCounts.map(([type, count]) => (
                <li key={type}>
                  <label className="flex items-center justify-between gap-2 cursor-pointer text-sm">
                    <span className="flex items-center gap-2">
                      <input type="checkbox" checked={!hidden.has(type)} onChange={() => toggle(type)}
                        aria-label={`Toggle ${TYPE_LABEL[type] ?? type}`} />
                      <span>{TYPE_LABEL[type] ?? type}</span>
                    </span>
                    <span className="text-xs text-gray-400 tabular-nums">{count}</span>
                  </label>
                </li>
              ))}
            </ul>
            <p className="text-[11px] text-gray-500 mt-4 leading-relaxed">
              Click a node to open its details. Drag to pan, wheel to zoom.
            </p>
          </aside>
        )}

        {/* Canvas + kill-chain labels overlay */}
        <div className="flex-1 min-h-0 p-3 relative">
          {isLoading ? <Loading /> : error || !data ? <ErrorCard error={error} /> : (
            <>
              <ThreatGraph graph={data} rootId={id} onSelect={onSelect} mode="fullscreen" layout={layout} onReady={onReady} />
              {scope && data.nodes.length <= 1 && (
                <div role="status" className="absolute inset-0 flex items-center justify-center pointer-events-none">
                  <div className="pointer-events-auto max-w-md bg-gray-900/90 border border-gray-700 rounded-lg p-6 text-center shadow-xl">
                    <h3 className="text-lg font-semibold mb-2">Nothing to show in this scope</h3>
                    <p className="text-sm text-gray-300 mb-4">
                      "This investigation" only shows facts whose citations come from this run. Older investigations
                      (before the scope column was added) are not linked to their claims, so their scoped view is empty.
                    </p>
                    {onClearScope && (
                      <button type="button" className="btn btn-primary btn-sm" onClick={onClearScope}>
                        Switch to Everything known
                      </button>
                    )}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>,
    document.body,
  )
}
