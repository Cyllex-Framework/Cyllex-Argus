import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const { nodeStore, layoutRun, fit } = vi.hoisted(() => ({
  nodeStore: [] as { data: Record<string, string>; style: ReturnType<typeof vi.fn> }[],
  layoutRun: vi.fn(),
  fit: vi.fn(),
}))
vi.mock('cytoscape', () => ({
  default: vi.fn((options: { elements: { group: string; data: Record<string, string> }[] }) => {
    nodeStore.length = 0
    for (const el of options.elements) {
      if (el.group === 'nodes') nodeStore.push({ data: el.data, style: vi.fn() })
    }
    return {
      options,
      on: vi.fn(),
      one: vi.fn(),
      maxZoom: vi.fn(),
      $id: vi.fn(() => ({ addClass: vi.fn() })),
      nodes: vi.fn(() => ({ forEach: (fn: (n: unknown) => void) => nodeStore.forEach((n) => fn({ data: (k: string) => n.data[k], style: n.style })) })),
      layout: vi.fn(() => ({ run: layoutRun })),
      fit,
      destroy: vi.fn(),
    }
  }),
}))

import cytoscape from 'cytoscape'
import { ThreatGraphFullscreen } from './ThreatGraphFullscreen'
import { mockApi, renderWithProviders } from '../../test/utils'

const GRAPH = {
  nodes: [
    { id: 'is--1', label: 'Scattered Spider', type: 'intrusion-set', attack: true },
    { id: 'ap--1', label: 'Spearphishing Voice', type: 'attack-pattern', attack: true },
    { id: 'mw--1', label: 'Malware X', type: 'malware', attack: true },
  ],
  edges: [{ id: 'is--1|uses|ap--1', source: 'is--1', target: 'ap--1', predicate: 'uses', status: 'single-source', confidence: 30 }],
}
const URL = 'GET /api/threats/is--1/graph?depth=3&limit=200'

beforeEach(() => vi.clearAllMocks())

test('enables wheel zoom and panning and covers the viewport', async () => {
  mockApi({ [URL]: GRAPH })
  renderWithProviders(<ThreatGraphFullscreen id="is--1" onClose={vi.fn()} onSelect={vi.fn()} />)
  const dialog = await screen.findByRole('dialog', { name: 'Relationship graph' })
  expect(dialog).toHaveClass('fixed', 'inset-0', 'z-50')
  await screen.findByTestId('threat-graph')
  const options = vi.mocked(cytoscape).mock.calls[0][0] as unknown as Record<string, unknown>
  expect(options).toMatchObject({ userZoomingEnabled: true, userPanningEnabled: true })
})

test('offers one filter toggle per node type present, and toggling hides those nodes', async () => {
  mockApi({ [URL]: GRAPH })
  renderWithProviders(<ThreatGraphFullscreen id="is--1" onClose={vi.fn()} onSelect={vi.fn()} />)
  const malware = await screen.findByLabelText('Toggle Malware')
  expect(screen.getByLabelText('Toggle Techniques')).toBeChecked()
  expect(screen.queryByLabelText('Toggle Tools')).not.toBeInTheDocument()
  await userEvent.click(malware)
  expect(malware).not.toBeChecked()
  expect(nodeStore.find((n) => n.data.type === 'malware')!.style).toHaveBeenLastCalledWith('display', 'none')
  expect(nodeStore.find((n) => n.data.type === 'attack-pattern')!.style).toHaveBeenLastCalledWith('display', 'element')
  await userEvent.click(malware)
  expect(nodeStore.find((n) => n.data.type === 'malware')!.style).toHaveBeenLastCalledWith('display', 'element')
})

test('identity, indicator and vulnerability nodes each get a filter toggle that hides them', async () => {
  const graph = {
    nodes: [
      ...GRAPH.nodes,
      { id: 'id--1', label: 'Okta', type: 'identity', attack: false },
      { id: 'in--1', label: 'evil.example', type: 'indicator', attack: false, freshness: 'active' },
      { id: 'vu--1', label: 'CVE-2024-1', type: 'vulnerability', attack: false },
    ],
    edges: GRAPH.edges,
  }
  mockApi({ [URL]: graph })
  renderWithProviders(<ThreatGraphFullscreen id="is--1" onClose={vi.fn()} onSelect={vi.fn()} />)
  for (const [type, label] of [['identity', 'Targets & Sectors'], ['indicator', 'Indicators'], ['vulnerability', 'Vulnerabilities']] as const) {
    const button = await screen.findByLabelText(`Toggle ${label}`)
    expect(button).toBeChecked()
    await userEvent.click(button)
    expect(nodeStore.find((n) => n.data.type === type)!.style).toHaveBeenLastCalledWith('display', 'none')
    await userEvent.click(button)
    expect(nodeStore.find((n) => n.data.type === type)!.style).toHaveBeenLastCalledWith('display', 'element')
  }
})

test('Fit reruns the layout', async () => {
  mockApi({ [URL]: GRAPH })
  renderWithProviders(<ThreatGraphFullscreen id="is--1" onClose={vi.fn()} onSelect={vi.fn()} />)
  await userEvent.click(await screen.findByRole('button', { name: 'Fit' }))
  expect(layoutRun).toHaveBeenCalled()
})

test('Escape and the Close button call onClose', async () => {
  mockApi({ [URL]: GRAPH })
  const onClose = vi.fn()
  renderWithProviders(<ThreatGraphFullscreen id="is--1" onClose={onClose} onSelect={vi.fn()} />)
  await screen.findByRole('button', { name: 'Fit' })
  await userEvent.keyboard('{Escape}')
  expect(onClose).toHaveBeenCalledTimes(1)
  await userEvent.click(screen.getByRole('button', { name: 'Close' }))
  expect(onClose).toHaveBeenCalledTimes(2)
})

test('shows a notice only when the payload is truncated', async () => {
  mockApi({ [URL]: { ...GRAPH, truncated: true } })
  const { unmount } = renderWithProviders(<ThreatGraphFullscreen id="is--1" onClose={vi.fn()} onSelect={vi.fn()} />)
  expect(await screen.findByRole('status')).toHaveTextContent('Showing 200 relationships. Narrow the view with filters or search.')
  unmount()
  mockApi({ [URL]: { ...GRAPH, truncated: false } })
  renderWithProviders(<ThreatGraphFullscreen id="is--1" onClose={vi.fn()} onSelect={vi.fn()} />)
  await screen.findByRole('button', { name: 'Fit' })
  expect(screen.queryByRole('status')).not.toBeInTheDocument()
})
