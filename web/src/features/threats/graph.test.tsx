import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useLocation } from 'react-router-dom'
import { graphStylesheet, nodeColor, toElements } from './graphModel'

const { handlers, addClass, destroy } = vi.hoisted(() => ({
  handlers: {} as Record<string, (event: { target: { id: () => string } }) => void>,
  addClass: vi.fn(),
  destroy: vi.fn(),
}))
vi.mock('cytoscape', () => ({
  default: vi.fn((options: { elements: unknown[] }) => ({
    options,
    on: vi.fn((event: string, selector: string, handler: (e: { target: { id: () => string } }) => void) => {
      handlers[`${event}:${selector}`] = handler
    }),
    one: vi.fn(), // layoutstop callback: ignored in tests, the mock layout never fires it
    maxZoom: vi.fn(),
    $id: vi.fn(() => ({ addClass })),
    nodes: vi.fn(() => ({ forEach: vi.fn() })),
    layout: vi.fn(() => ({ run: vi.fn() })),
    fit: vi.fn(),
    destroy,
  })),
}))

import cytoscape from 'cytoscape'
import { ThreatGraph, ThreatGraphCard } from './ThreatGraph'
import { mockApi, renderWithProviders } from '../../test/utils'

beforeEach(() => {
  vi.clearAllMocks() // call counts (cytoscape, addClass, destroy) must not leak between tests
})

const GRAPH = {
  nodes: [
    { id: 'is--1', label: 'Scattered Spider', type: 'intrusion-set', attack: true },
    { id: 'ap--1', label: 'Spearphishing Voice (T1566.004)', type: 'attack-pattern', attack: true },
  ],
  edges: [{ id: 'is--1|uses|ap--1', source: 'is--1', target: 'ap--1', predicate: 'uses', status: 'single-source', confidence: 30 }],
}

test('toElements maps nodes and edges with colors and labels', () => {
  const elements = toElements(GRAPH as never, '#c0c0c0')
  expect(elements).toHaveLength(3)
  expect(elements[0].data).toMatchObject({ id: 'is--1', label: 'Scattered Spider', color: '#c0c0c0' })
  expect(elements[1].data).toMatchObject({ color: nodeColor('attack-pattern', '#c0c0c0') })
  expect(elements[2].data).toMatchObject({ source: 'is--1', target: 'ap--1', label: 'uses', status: 'single-source' })
  expect(nodeColor('unknown-type', '#c0c0c0')).toBe('#9ca3af')
})

test('new node types get their own colours and indicators carry freshness into the element data', () => {
  expect(nodeColor('identity', '#c0c0c0')).toBe('#64748b')
  expect(nodeColor('indicator', '#c0c0c0')).toBe('#14b8a6')
  expect(nodeColor('vulnerability', '#c0c0c0')).toBe('#e11d48')
  const graph = { nodes: [
    { id: 'in--1', label: 'evil.example', type: 'indicator', attack: false, freshness: 'active' },
    { id: 'mw--1', label: 'X', type: 'malware', attack: false },
  ], edges: [] }
  const [indicator, malware] = toElements(graph as never, '#c0c0c0')
  expect(indicator.data).toMatchObject({ freshness: 'active' })
  expect(malware.data).not.toHaveProperty('freshness')
  const sheet = graphStylesheet('#1a1a1e') as { selector: string; style: Record<string, unknown> }[]
  const ring = (value: string) => sheet.find((rule) => rule.selector === `node[freshness = "${value}"]`)!.style
  expect(ring('active')['border-color']).toBe('#10b981')
  expect(ring('dormant')['border-color']).toBe('#f59e0b')
  expect(ring('historical')['border-color']).toBe('#9ca3af')
  expect(ring('unknown')['border-style']).toBe('dashed')
})

test('ThreatGraph builds a cytoscape instance, marks the root and reports node taps', () => {
  const onSelect = vi.fn()
  const { unmount } = render(<ThreatGraph graph={GRAPH as never} rootId="is--1" onSelect={onSelect} />)
  expect(screen.getByTestId('threat-graph')).toBeInTheDocument()
  expect(vi.mocked(cytoscape)).toHaveBeenCalledTimes(1)
  expect(addClass).toHaveBeenCalledWith('root')
  handlers['tap:node']({ target: { id: () => 'ap--1' } })
  expect(onSelect).toHaveBeenCalledWith('ap--1')
  unmount()
  expect(destroy).toHaveBeenCalled()
})

test('a sparse graph can zoom up so nodes fill the embedded pane, but never past the fullscreen cap', () => {
  render(<ThreatGraph graph={GRAPH as never} rootId="is--1" onSelect={vi.fn()} />)
  const options = vi.mocked(cytoscape).mock.calls[0][0] as unknown as { maxZoom?: number; layout: { padding?: number } }
  // 2 nodes -> the "<=5" bucket: cap at 2.2 so a sparse graph does not render tiny.
  expect(options.maxZoom).toBeGreaterThanOrEqual(2.0)
  expect(options.maxZoom).toBeLessThanOrEqual(2.5)
  expect(options.layout.padding).toBeGreaterThanOrEqual(30)
})

test('node and edge labels sit on the canvas color so crossing lines do not run through the text', () => {
  const sheet = graphStylesheet('#1a1a1e') as { selector: string; style: Record<string, unknown> }[]
  for (const selector of ['node', 'edge']) {
    const style = sheet.find((rule) => rule.selector === selector)!.style
    expect(style['text-background-color']).toBe('#1a1a1e')
    expect(style['text-background-opacity']).toBeGreaterThan(0.5)
  }
})

test('ThreatGraphCard loads the graph, toggles depth and shows an empty state', async () => {
  const fetchMock = mockApi({ 'GET /api/threats/is--1/graph?depth=1': GRAPH, 'GET /api/threats/is--1/graph?depth=2': { nodes: [], edges: [] } })
  renderWithProviders(<ThreatGraphCard id="is--1" />)
  expect(await screen.findByTestId('threat-graph')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Depth 2' }))
  expect(await screen.findByText(/No relationships to draw/)).toBeInTheDocument()
  expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('depth=2'))).toBe(true)
})

test('the depth toggle marks the active depth and moves the mark when another depth is picked', async () => {
  mockApi({ 'GET /api/threats/is--1/graph?depth=1': GRAPH, 'GET /api/threats/is--1/graph?depth=2': GRAPH })
  renderWithProviders(<ThreatGraphCard id="is--1" />)
  const depth1 = screen.getByRole('button', { name: 'Depth 1' })
  const depth2 = screen.getByRole('button', { name: 'Depth 2' })
  expect(depth1).toHaveAttribute('aria-pressed', 'true')
  expect(depth1).toHaveClass('active') // the vendored `.btn-group .btn.active` rule is what paints the active state
  expect(depth2).toHaveAttribute('aria-pressed', 'false')
  expect(depth2).not.toHaveClass('active')
  await userEvent.click(depth2)
  expect(depth2).toHaveAttribute('aria-pressed', 'true')
  expect(depth2).toHaveClass('active')
  expect(depth1).toHaveAttribute('aria-pressed', 'false')
  expect(depth1).not.toHaveClass('active')
  await screen.findByTestId('threat-graph')
})

function LocationProbe() {
  const { pathname, key } = useLocation() // a navigation to the current path still changes `key`
  return <p data-testid="location" data-key={key}>{pathname}</p>
}

test('tapping another node opens its profile, tapping the root does not navigate', async () => {
  mockApi({ 'GET /api/threats/is--1/graph?depth=1': GRAPH })
  renderWithProviders(<><ThreatGraphCard id="is--1" /><LocationProbe /></>, { route: '/threats/is--1', path: '/threats/:id' })
  await screen.findByTestId('threat-graph')
  const probe = screen.getByTestId('location')
  const startKey = probe.getAttribute('data-key')
  act(() => handlers['tap:node']({ target: { id: () => 'is--1' } }))
  expect(probe).toHaveTextContent('/threats/is--1')
  expect(probe).toHaveAttribute('data-key', startKey!)
  act(() => handlers['tap:node']({ target: { id: () => 'ap--1' } }))
  expect(probe).toHaveTextContent('/threats/ap--1')
  expect(probe).not.toHaveAttribute('data-key', startKey!)
})

test('ThreatGraph enables wheel zoom BloodHound-style (hover canvas = zoom) with a noticeable per-tick step', () => {
  render(<ThreatGraph graph={GRAPH as never} rootId="is--1" onSelect={vi.fn()} />)
  const options = vi.mocked(cytoscape).mock.calls[0][0] as unknown as Record<string, unknown>
  expect(options).toMatchObject({ userZoomingEnabled: true, userPanningEnabled: true, boxSelectionEnabled: false })
  // A single wheel notch should move the zoom visibly: anything below ~0.4 is a crawl on this UI.
  expect(options.wheelSensitivity).toBeGreaterThanOrEqual(0.4)
})

test('ThreatGraph rebuilds only when its inputs change', () => {
  const onSelect = vi.fn()
  const { rerender } = render(<ThreatGraph graph={GRAPH as never} rootId="is--1" onSelect={onSelect} />)
  rerender(<ThreatGraph graph={GRAPH as never} rootId="is--1" onSelect={onSelect} />)
  expect(vi.mocked(cytoscape)).toHaveBeenCalledTimes(1)
  expect(destroy).not.toHaveBeenCalled()
  rerender(<ThreatGraph graph={{ ...GRAPH } as never} rootId="is--1" onSelect={onSelect} />)
  expect(vi.mocked(cytoscape)).toHaveBeenCalledTimes(2)
  expect(destroy).toHaveBeenCalledTimes(1)
})

test('switching depth destroys the old instance and builds a new one; a refetch of equal data does not rebuild', async () => {
  const wider = {
    nodes: [...GRAPH.nodes, { id: 'mw--1', label: 'Malware X', type: 'malware', attack: true }],
    edges: [...GRAPH.edges, { id: 'ap--1|uses|mw--1', source: 'ap--1', target: 'mw--1', predicate: 'uses', status: 'corroborated', confidence: 70 }],
  }
  const fetchMock = mockApi({ 'GET /api/threats/is--1/graph?depth=1': GRAPH, 'GET /api/threats/is--1/graph?depth=2': wider })
  const { queryClient } = renderWithProviders(<ThreatGraphCard id="is--1" />)
  await screen.findByTestId('threat-graph')
  expect(vi.mocked(cytoscape)).toHaveBeenCalledTimes(1)

  // Same data again (structural sharing keeps the reference): the instance must survive the refetch.
  await act(async () => { await queryClient.invalidateQueries() })
  expect(fetchMock.mock.calls.filter(([url]) => String(url).endsWith('depth=1'))).toHaveLength(2)
  expect(vi.mocked(cytoscape)).toHaveBeenCalledTimes(1)
  expect(destroy).not.toHaveBeenCalled()

  await userEvent.click(screen.getByRole('button', { name: 'Depth 2' }))
  await waitFor(() => expect(vi.mocked(cytoscape)).toHaveBeenCalledTimes(2))
  expect(destroy).toHaveBeenCalledTimes(1)
  expect((vi.mocked(cytoscape).mock.calls[1][0] as unknown as { elements: unknown[] }).elements).toHaveLength(5)
})

test('embedded ThreatGraphCard offers one toggle per node type present, with its count, and toggling hides those nodes', async () => {
  const wider = {
    nodes: [
      ...GRAPH.nodes,
      { id: 'mw--1', label: 'Malware X', type: 'malware', attack: true },
      { id: 'mw--2', label: 'Malware Y', type: 'malware', attack: true },
      { id: 'in--1', label: 'evil.example', type: 'indicator', attack: false, freshness: 'active' },
    ],
    edges: GRAPH.edges,
  }
  mockApi({ 'GET /api/threats/is--1/graph?depth=1': wider })
  renderWithProviders(<ThreatGraphCard id="is--1" />)
  // Every type present appears with its count; the three absent types do not.
  const actor = await screen.findByRole('button', { name: 'Toggle Actor' })
  const techniques = screen.getByRole('button', { name: 'Toggle Techniques' })
  const malware = screen.getByRole('button', { name: 'Toggle Malware' })
  const indicators = screen.getByRole('button', { name: 'Toggle Indicators' })
  expect(screen.queryByRole('button', { name: 'Toggle Tools' })).not.toBeInTheDocument()
  for (const btn of [actor, techniques, malware, indicators]) expect(btn).toHaveAttribute('aria-pressed', 'true')
  // Counts render next to the type label.
  expect(malware).toHaveTextContent('2')
  expect(techniques).toHaveTextContent('1')
  // Toggle Malware off: button flips, click again flips it back.
  await userEvent.click(malware)
  expect(malware).toHaveAttribute('aria-pressed', 'false')
  await userEvent.click(malware)
  expect(malware).toHaveAttribute('aria-pressed', 'true')
})

test('embedded mode shows an Expand button that reports a click, and wheel zoom is on', async () => {
  const onExpand = vi.fn()
  render(<ThreatGraph graph={GRAPH as never} rootId="is--1" onSelect={vi.fn()} onExpand={onExpand} />)
  await userEvent.click(screen.getByRole('button', { name: 'Expand graph' }))
  expect(onExpand).toHaveBeenCalledTimes(1)
  const options = vi.mocked(cytoscape).mock.calls[0][0] as unknown as Record<string, unknown>
  expect(options.userZoomingEnabled).toBe(true)
})

test('without onExpand there is no Expand button', () => {
  render(<ThreatGraph graph={GRAPH as never} rootId="is--1" onSelect={vi.fn()} />)
  expect(screen.queryByRole('button', { name: 'Expand graph' })).not.toBeInTheDocument()
})

test('the card opens the fullscreen graph on Expand, fetching depth 3 with a limit of 200', async () => {
  const fetchMock = mockApi({
    'GET /api/threats/is--1/graph?depth=1': GRAPH,
    'GET /api/threats/is--1/graph?depth=3&limit=200': { ...GRAPH, truncated: true },
  })
  renderWithProviders(<ThreatGraphCard id="is--1" />)
  await screen.findByTestId('threat-graph')
  expect(fetchMock.mock.calls.some(([url]) => String(url).includes('limit=200'))).toBe(false)
  await userEvent.click(screen.getByRole('button', { name: 'Expand graph' }))
  expect(await screen.findByRole('dialog', { name: 'Relationship graph' })).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Close' }))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})
