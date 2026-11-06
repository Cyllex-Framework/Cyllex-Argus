import type cytoscape from 'cytoscape'
import type { Graph } from '../../api/types'

/** The 14 MITRE ATT&CK Enterprise tactics, in canonical kill-chain order. */
export const TACTICS: readonly { id: string; name: string }[] = [
  { id: 'reconnaissance', name: 'Reconnaissance' },
  { id: 'resource-development', name: 'Resource Dev.' },
  { id: 'initial-access', name: 'Initial Access' },
  { id: 'execution', name: 'Execution' },
  { id: 'persistence', name: 'Persistence' },
  { id: 'privilege-escalation', name: 'Privilege Esc.' },
  { id: 'defense-evasion', name: 'Defense Evasion' },
  { id: 'credential-access', name: 'Credential Access' },
  { id: 'discovery', name: 'Discovery' },
  { id: 'lateral-movement', name: 'Lateral Movement' },
  { id: 'collection', name: 'Collection' },
  { id: 'command-and-control', name: 'C2' },
  { id: 'exfiltration', name: 'Exfiltration' },
  { id: 'impact', name: 'Impact' },
]

const UNCLASSIFIED = 'unclassified'

/** Non-technique node types get their own lane below the techniques, in this reading order. */
const NODE_LANES: readonly { id: string; name: string }[] = [
  { id: 'campaign', name: 'Campaigns' },
  { id: 'malware', name: 'Malware' },
  { id: 'tool', name: 'Tools' },
  { id: 'identity', name: 'Targets & Sectors' },
  { id: 'indicator', name: 'Indicators' },
  { id: 'vulnerability', name: 'Vulnerabilities' },
  { id: 'location', name: 'Locations' },
]

const COLUMN_WIDTH = 220
const ROW_HEIGHT = 70
const LANE_ROW_HEIGHT = 70
const ROOT_Y = 40             // The APT sits at the very top of the canvas.
const HEADER_Y = 190          // Tactic headers sit just below the APT.
const TECHNIQUE_TOP = 260     // First technique row.
const LANE_GAP = 100          // Vertical space between the techniques and the first lane.

export interface LaneMeta {
  columns: readonly { id: string; name: string; x: number }[]
  lanes: readonly { id: string; name: string; y: number; count: number }[]
  width: number
  height: number
  headerY: number
  rootId: string
}

/**
 * A "hub-and-lanes" layout centred on the APT:
 *   - the root actor sits at the top centre, larger than everything else;
 *   - only tactics that contain at least one observed technique become a column, so the canvas stays compact;
 *   - techniques stack vertically inside their tactic column;
 *   - every other node type gets its own labelled lane below the techniques.
 *
 * Returns positions for cytoscape's `preset` layout and the column/lane metadata the fullscreen view uses
 * to render tactic and lane labels aligned with the canvas.
 */
export function killChainPositions(graph: Graph, rootId: string): {
  positions: Record<string, cytoscape.Position>
  meta: LaneMeta
} {
  const positions: Record<string, cytoscape.Position> = {}

  // Group techniques by tactic, keeping only tactics that have at least one entry.
  const techniqueColumns = new Map<string, string[]>()
  for (const node of graph.nodes) {
    if (node.id === rootId) continue
    if (node.type !== 'attack-pattern') continue
    const tactic = node.tactic && TACTICS.some((t) => t.id === node.tactic) ? node.tactic : UNCLASSIFIED
    if (!techniqueColumns.has(tactic)) techniqueColumns.set(tactic, [])
    techniqueColumns.get(tactic)!.push(node.id)
  }
  const orderedTactics = [
    ...TACTICS.filter((t) => techniqueColumns.has(t.id)),
    ...(techniqueColumns.has(UNCLASSIFIED) ? [{ id: UNCLASSIFIED, name: 'Untagged' }] : []),
  ]

  const canvasWidth = Math.max(orderedTactics.length * COLUMN_WIDTH, 3 * COLUMN_WIDTH)
  const columns = orderedTactics.map((t, index) => ({
    id: t.id, name: t.name,
    // Centre the column set horizontally, so a single tactic sits in the middle of the canvas.
    x: (canvasWidth - orderedTactics.length * COLUMN_WIDTH) / 2 + index * COLUMN_WIDTH + COLUMN_WIDTH / 2,
  }))

  // Root at the top centre.
  positions[rootId] = { x: canvasWidth / 2, y: ROOT_Y }

  // Techniques stack under their tactic header.
  let maxColumnHeight = 0
  for (const tactic of orderedTactics) {
    const ids = techniqueColumns.get(tactic.id) ?? []
    const column = columns.find((c) => c.id === tactic.id)!
    ids.forEach((id, row) => {
      positions[id] = { x: column.x, y: TECHNIQUE_TOP + row * ROW_HEIGHT }
    })
    maxColumnHeight = Math.max(maxColumnHeight, ids.length)
  }
  const techniqueBandBottom = TECHNIQUE_TOP + maxColumnHeight * ROW_HEIGHT

  // Non-technique node types go into labelled lanes below the techniques.
  const byType = new Map<string, string[]>()
  for (const node of graph.nodes) {
    if (node.id === rootId || node.type === 'attack-pattern') continue
    if (!byType.has(node.type)) byType.set(node.type, [])
    byType.get(node.type)!.push(node.id)
  }
  const laneDefs = [
    ...NODE_LANES.filter((lane) => byType.has(lane.id)),
    ...[...byType.keys()].filter((type) => !NODE_LANES.some((l) => l.id === type)).sort().map((type) => ({ id: type, name: type })),
  ]

  const perRow = Math.max(3, Math.floor(canvasWidth / COLUMN_WIDTH))
  const lanes: { id: string; name: string; y: number; count: number }[] = []
  let cursor = techniqueBandBottom + LANE_GAP
  for (const lane of laneDefs) {
    const ids = byType.get(lane.id) ?? []
    lanes.push({ id: lane.id, name: lane.name, y: cursor, count: ids.length })
    ids.forEach((id, index) => {
      const row = Math.floor(index / perRow)
      const col = index % perRow
      // Centre each row of nodes horizontally within the canvas.
      const usedInRow = Math.min(perRow, ids.length - row * perRow)
      const rowXOffset = (canvasWidth - usedInRow * COLUMN_WIDTH) / 2 + COLUMN_WIDTH / 2
      positions[id] = { x: rowXOffset + col * COLUMN_WIDTH, y: cursor + row * LANE_ROW_HEIGHT }
    })
    const rowsUsed = Math.max(1, Math.ceil(ids.length / perRow))
    cursor += rowsUsed * LANE_ROW_HEIGHT + LANE_GAP
  }

  return {
    positions,
    meta: {
      columns, lanes, width: canvasWidth, height: cursor,
      headerY: HEADER_Y, rootId,
    },
  }
}
