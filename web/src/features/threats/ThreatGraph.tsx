import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import cytoscape from 'cytoscape'
import { useGraph } from '../../api/hooks'
import type { Graph } from '../../api/types'
import { Card } from '../../components/Card'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'
import { ThreatGraphFullscreen } from './ThreatGraphFullscreen'
import { TYPE_LABEL, graphStylesheet, toElements } from './graphModel'
import { killChainPositions } from './killChainLayout'

function themeColor(name: string, fallback: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback
}

// Long ideal edges leave room for the node labels and the predicate on each edge.
export const GRAPH_LAYOUT = { name: 'cose', animate: false, padding: 40, idealEdgeLength: () => 140, nodeRepulsion: () => 400000 } as const

/** Sparse graphs get more aire between nodes so they fill the pane; dense ones keep the default. */
function layoutForSize(nodeCount: number): typeof GRAPH_LAYOUT {
  const edge = nodeCount <= 10 ? 180 : 140
  const repulsion = nodeCount <= 10 ? 600000 : 400000
  return { ...GRAPH_LAYOUT, idealEdgeLength: () => edge, nodeRepulsion: () => repulsion }
}

/** Cap zoom higher when there are few nodes so the auto-fit does not leave them tiny. */
function embeddedMaxZoom(nodeCount: number): number {
  if (nodeCount <= 5) return 2.2
  if (nodeCount <= 15) return 1.8
  if (nodeCount <= 30) return 1.5
  return 1.3
}

export type GraphLayout = 'force' | 'kill-chain'

interface ThreatGraphProps {
  graph: Graph
  rootId: string
  onSelect: (id: string) => void
  /** `embedded` (default): no wheel zoom so the page keeps scrolling. `fullscreen`: wheel zoom on. */
  mode?: 'embedded' | 'fullscreen'
  /** Layout algorithm: 'force' is the physics cose layout; 'kill-chain' arranges techniques in MITRE tactic columns. */
  layout?: GraphLayout
  /** Embedded mode only: shows the "Expand" button. */
  onExpand?: () => void
  /** Embedded mode only: fills a wide pane, at least 600px high and growing with the viewport. */
  tall?: boolean
  /** Receives the live cytoscape instance (null on teardown), so a parent can filter or refit it. */
  onReady?: (cy: cytoscape.Core | null) => void
}

export function ThreatGraph({ graph, rootId, onSelect, mode = 'embedded', layout = 'force', onExpand, tall, onReady }: ThreatGraphProps) {
  const container = useRef<HTMLDivElement>(null)
  const fullscreen = mode === 'fullscreen'
  useEffect(() => {
    if (!container.current) return
    const layoutConfig = layout === 'kill-chain'
      ? { name: 'preset', positions: killChainPositions(graph, rootId).positions, fit: true, padding: 60 }
      : layoutForSize(graph.nodes.length)
    // The initial fit uses the embedded cap so a sparse graph is not blown up; once the layout settles
    // we open the cap wide so manual zoom can push much deeper. Fullscreen already starts open.
    const initialMax = fullscreen ? 12 : embeddedMaxZoom(graph.nodes.length)
    const cy = cytoscape({
      container: container.current,
      elements: toElements(graph, themeColor('--accent-color', '#c0c0c0')),
      style: graphStylesheet(themeColor('--bg-primary', '#1a1a1e')),
      layout: layoutConfig,
      // Deep range: zoom out until the whole graph is a dot, zoom in until a single node fills the pane.
      minZoom: 0.02,
      maxZoom: initialMax,
      // BloodHound-style wheel zoom in both modes: over the canvas = zoom, over the page = page scroll.
      // Aggressive sensitivity: one wheel notch should feel like a real step, not a nudge.
      userZoomingEnabled: true,
      wheelSensitivity: 1.1,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
    })
    // Once the layout has fitted the graph into the pane, open the cap so manual zoom can push much further.
    cy.one('layoutstop', () => cy.maxZoom(12))
    cy.$id(rootId).addClass('root')
    cy.on('tap', 'node', (event) => onSelect(event.target.id()))
    onReady?.(cy)
    // Browser tests need node positions to click a canvas node; a DOM property keeps that off `window`.
    const host = container.current as HTMLDivElement & { __cy?: cytoscape.Core }
    host.__cy = cy
    return () => {
      delete host.__cy
      onReady?.(null)
      cy.destroy()
    }
  }, [graph, rootId, onSelect, fullscreen, onReady, layout])
  return (
    <div className={`relative ${fullscreen ? 'w-full h-full' : ''}`}>
      <div ref={container} data-testid="threat-graph" role="img" aria-label="Relationship graph"
        style={tall && !fullscreen ? { height: 'max(600px, calc(100vh - 320px))' } : undefined}
        className={`w-full bg-gray-900 border border-gray-700 ${fullscreen ? 'h-full' : tall ? '' : 'h-[480px]'}`} />
      {!fullscreen && onExpand && (
        <button type="button" aria-label="Expand graph" title="Expand graph" onClick={onExpand}
          className="btn btn-secondary btn-sm absolute top-2 right-2">
          Expand
        </button>
      )}
    </div>
  )
}

export function ThreatGraphCard({ id }: { id: string }) {
  const [depth, setDepth] = useState<1 | 2>(1)
  const [expanded, setExpanded] = useState(false)
  const [hidden, setHidden] = useState<ReadonlySet<string>>(new Set())
  const [cy, setCy] = useState<cytoscape.Core | null>(null)
  const { data, error, isLoading } = useGraph(id, depth)
  const navigate = useNavigate()
  const onSelect = useCallback((nodeId: string) => {
    if (nodeId !== id) navigate(`/threats/${encodeURIComponent(nodeId)}`)
  }, [id, navigate])
  const onReady = useCallback((instance: cytoscape.Core | null) => setCy(instance), [])

  // One chip per type currently in the graph, with its count. Alphabetical so the row is stable
  // across refetches that reorder nodes under the hood.
  const typeCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const node of data?.nodes ?? []) counts.set(node.type, (counts.get(node.type) ?? 0) + 1)
    return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b))
  }, [data])

  // Hide via display, not by rebuilding elements: cheaper, and the layout survives the toggle —
  // same approach the fullscreen drawer uses.
  useEffect(() => {
    if (!cy) return
    cy.nodes().forEach((node) => {
      node.style('display', hidden.has(String(node.data('type'))) ? 'none' : 'element')
    })
  }, [cy, hidden])

  // Switching depth drops the old graph; stale hidden entries from the old depth would silently
  // hide nodes of a type that just reappeared, so we reset to "all on" whenever the data changes.
  useEffect(() => { setHidden(new Set()) }, [data])

  const toggle = (type: string) =>
    setHidden((current) => {
      const next = new Set(current)
      if (!next.delete(type)) next.add(type)
      return next
    })

  const actions = (
    <div className="flex items-center gap-3 flex-wrap">
      <div className="btn-group">
        {([1, 2] as const).map((d) => (
          <button key={d} type="button" className={`btn btn-sm ${depth === d ? 'active' : ''}`} aria-pressed={depth === d} onClick={() => setDepth(d)}>
            Depth {d}
          </button>
        ))}
      </div>
      {typeCounts.length > 0 && (
        <div className="btn-group flex-wrap">
          {typeCounts.map(([type, count]) => {
            const on = !hidden.has(type)
            return (
              <button key={type} type="button" aria-label={`Toggle ${TYPE_LABEL[type] ?? type}`} aria-pressed={on}
                className={`btn btn-sm ${on ? 'active' : ''}`}
                onClick={() => toggle(type)}>
                {TYPE_LABEL[type] ?? type} <span className="opacity-60 ml-1 tabular-nums">{count}</span>
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
  return (
    <Card title="Relationship graph" actions={actions}>
      {isLoading ? <Loading /> : error || !data ? <ErrorCard error={error} /> : data.edges.length === 0 ? (
        <EmptyState>No relationships to draw yet.</EmptyState>
      ) : (
        <>
          <ThreatGraph graph={data} rootId={id} onSelect={onSelect} onExpand={() => setExpanded(true)} onReady={onReady} />
          <p className="text-xs text-gray-500 mt-2">
            Solid: corroborated · dashed: single source · red: contested. Click a node to open its profile.
          </p>
        </>
      )}
      {expanded && (
        <Suspense fallback={null}>
          <ThreatGraphFullscreen id={id} onClose={() => setExpanded(false)} onSelect={onSelect} />
        </Suspense>
      )}
    </Card>
  )
}
