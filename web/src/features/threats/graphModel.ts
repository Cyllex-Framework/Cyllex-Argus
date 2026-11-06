import type cytoscape from 'cytoscape'
import type { Graph } from '../../api/types'

// Human labels for the node-type filter chips. Shared between the embedded card
// (header chips) and the fullscreen drawer (checkboxes) so a type reads the same
// in both views. Keep in sync with NODE_COLORS entries.
export const TYPE_LABEL: Record<string, string> = {
  'intrusion-set': 'Actor',
  campaign: 'Campaigns',
  malware: 'Malware',
  tool: 'Tools',
  'attack-pattern': 'Techniques',
  identity: 'Targets & Sectors',
  indicator: 'Indicators',
  vulnerability: 'Vulnerabilities',
  location: 'Locations',
}

export const NODE_COLORS: Record<string, string> = {
  campaign: '#38bdf8',
  malware: '#f87171',
  tool: '#fbbf24',
  'attack-pattern': '#34d399',
  vulnerability: '#e11d48',
  identity: '#64748b',
  location: '#94a3b8',
  indicator: '#14b8a6',
}
const FALLBACK = '#9ca3af'

export function nodeColor(type: string, accent: string): string {
  if (type === 'intrusion-set') return accent
  return NODE_COLORS[type] ?? FALLBACK
}

export function toElements(graph: Graph, accent: string): cytoscape.ElementDefinition[] {
  return [
    ...graph.nodes.map((node) => ({
      group: 'nodes' as const,
      data: { id: node.id, label: node.label, type: node.type, color: nodeColor(node.type, accent), attack: node.attack ? 1 : 0, ...(node.freshness ? { freshness: node.freshness } : {}) },
    })),
    ...graph.edges.map((edge) => ({
      group: 'edges' as const,
      data: { id: edge.id, source: edge.source, target: edge.target, label: edge.predicate, status: edge.status, confidence: edge.confidence },
    })),
  ]
}

// Labels sit on the canvas color, so a line crossing a label never runs through its text.
export function graphStylesheet(background: string): cytoscape.StylesheetJson {
  const label = { 'text-background-color': background, 'text-background-opacity': 0.9, 'text-background-padding': '3px' }
  return [
    {
      selector: 'node',
      style: {
        'background-color': 'data(color)', label: 'data(label)', color: '#f0f0f0', 'font-size': 13,
        'text-valign': 'bottom', 'text-margin-y': 6, width: 28, height: 28, 'text-wrap': 'ellipsis', 'text-max-width': '180px', ...label,
      },
    },
    { selector: 'node.root', style: {
        width: 64, height: 64, 'border-width': 3, 'border-color': '#ffffff', 'font-size': 16,
        'font-weight': 700, 'text-margin-y': 10,
    } },
    // Freshness ring on indicator nodes: green active, amber dormant, grey historical, dashed grey unknown.
    { selector: 'node[freshness = "active"]', style: { 'border-width': 3, 'border-color': '#10b981' } },
    { selector: 'node[freshness = "dormant"]', style: { 'border-width': 3, 'border-color': '#f59e0b' } },
    { selector: 'node[freshness = "historical"]', style: { 'border-width': 3, 'border-color': '#9ca3af' } },
    { selector: 'node[freshness = "unknown"]', style: { 'border-width': 2, 'border-color': '#9ca3af', 'border-style': 'dashed' } },
    {
      selector: 'edge',
      style: {
        width: 1.5, 'line-color': '#6b7280', 'target-arrow-color': '#6b7280', 'target-arrow-shape': 'triangle',
        'curve-style': 'bezier', label: 'data(label)', 'font-size': 12, 'font-weight': 600,
        color: '#d1d5db', 'text-rotation': 'autorotate', ...label,
      },
    },
    { selector: 'edge[status = "single-source"]', style: { 'line-style': 'dashed' } },
    { selector: 'edge[status = "contested"]', style: { 'line-color': '#ef4444', 'target-arrow-color': '#ef4444' } },
  ]
}
