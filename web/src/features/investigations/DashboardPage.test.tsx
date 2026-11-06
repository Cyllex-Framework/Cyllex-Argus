import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

// A stand-in for cytoscape that remembers each instance's node-tap handler, so a test can tap a node.
const { instances } = vi.hoisted(() => ({ instances: [] as { tap: (id: string) => void }[] }))
vi.mock('cytoscape', () => ({
  default: vi.fn(() => {
    let onTap: ((event: unknown) => void) | null = null
    instances.push({ tap: (id) => onTap?.({ target: { id: () => id } }) })
    return {
      on: vi.fn((_event: string, _selector: string, fn: (event: unknown) => void) => { onTap = fn }),
      one: vi.fn(),
      maxZoom: vi.fn(),
      $id: vi.fn(() => ({ addClass: vi.fn() })),
      nodes: vi.fn(() => ({ forEach: vi.fn() })),
      layout: vi.fn(() => ({ run: vi.fn() })),
      fit: vi.fn(),
      destroy: vi.fn(),
    }
  }),
}))

import type { Job, Tactic } from '../../api/types'
import { mockApi, renderWithProviders } from '../../test/utils'
import { DashboardPage } from './DashboardPage'

const NAMES = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact']
const tactics = (withTechnique: boolean): Tactic[] => NAMES.map((name, i) => ({
  id: `TA${i}`, name,
  techniques: withTechnique && i === 2
    ? [{ id: 'ap--1', external_id: 'T1566.004', name: 'Spearphishing Voice', status: 'corroborated', confidence: 40, admiralty: 'B2', sources: 2 }]
    : [],
}))

const ENTITY = {
  id: 'is--1', stix_type: 'intrusion-set', name: 'Scattered Spider', external_id: null, attack: false,
  aliases: [{ alias: 'UNC3944', origin: 'attack' }],
}
const ref = (id: string, name: string, type = 'attack-pattern') => ({ id, stix_type: type, name, external_id: null, attack: true, label: name })
const PROFILE = {
  entity: ref('is--1', 'Scattered Spider', 'intrusion-set'),
  aliases: [],
  facts: [{
    subject: ref('is--1', 'Scattered Spider', 'intrusion-set'), predicate: 'uses', object: ref('ap--1', 'Spearphishing Voice'),
    status: 'corroborated', confidence: 60, admiralty: 'B2', first_seen: null, last_seen: null, source_count: 2, citations: [],
  }],
}
const GRAPH = {
  nodes: [
    { id: 'is--1', label: 'Scattered Spider', type: 'intrusion-set', attack: false },
    { id: 'ap--1', label: 'Spearphishing Voice', type: 'attack-pattern', attack: true },
  ],
  edges: [{ id: 'e1', source: 'is--1', target: 'ap--1', predicate: 'uses', status: 'corroborated', confidence: 60 }],
}
const SETTINGS_OK = { attack: { present: true, techniques: 1, groups: 1, software: 1 }, claude: { found: true }, config: {}, home: '' }

const EMPTY_USAGE = { by_stage: {}, total: { calls: 0, input_tokens: 0, output_tokens: 0, total_tokens: 0, cost_usd: 0 } }

function dashboard(over: Record<string, unknown> = {}, entity: unknown = ENTITY) {
  return {
    investigation: {
      id: 12, target: 'Octo Tempest', state: 'finished', started_at: '2026-09-29T14:31:02Z', finished_at: '2026-09-29T14:33:47Z',
      failure_reason: null, counts: { validated: 2, irrelevant: 1, failed: 1 }, token_usage: EMPTY_USAGE, ...over,
    },
    entity,
    attack_matrix: { tactics: tactics(entity !== null) },
  }
}

const job = (over: Partial<Job>): Job => ({
  id: 'j1', kind: 'investigate', params: { target: 'Octo Tempest' }, state: 'running', created_at: '', started_at: null,
  finished_at: null, message: null, result: null, events: 0, ...over,
})

const CATALOG = {
  tactics: NAMES.map((name, i) => ({
    id: `TA${i}`, name,
    techniques: i === 2 ? [{ id: 'ap--1', external_id: 'T1566.004', name: 'Spearphishing Voice', tactics: ['TA2'] }] : [],
  })),
}

function routes(extra: Record<string, unknown> = {}) {
  return {
    'GET /api/investigations/12/dashboard': dashboard(),
    'GET /api/settings': SETTINGS_OK,
    'GET /api/jobs': [],
    'GET /api/attack/catalog': CATALOG,
    'GET /api/threats/is--1': PROFILE,
    'GET /api/threats/ap--1': { ...PROFILE, entity: ref('ap--1', 'Spearphishing Voice') },
    'GET /api/threats/is--1/graph': GRAPH,
    ...extra,
  }
}

const renderPage = (search = '') =>
  renderWithProviders(<DashboardPage />, { route: `/investigations/12/dashboard${search}`, path: '/investigations/:id/dashboard' })
const openSection = (name: string) => userEvent.click(screen.getByRole('button', { name: new RegExp(`^${name}`) }))

beforeEach(() => {
  instances.length = 0
})

test('finished: lands on the matrix with the header, and every other section is one click away', async () => {
  mockApi(routes())
  renderPage()
  expect(await screen.findByRole('heading', { name: 'Scattered Spider' })).toBeInTheDocument()
  expect(screen.getByText('finished')).toBeInTheDocument()
  expect(await screen.findByRole('heading', { name: 'Initial Access' })).toBeInTheDocument()
  expect(screen.queryByTestId('threat-graph')).not.toBeInTheDocument()
  await openSection('Relationship graph')
  expect(await screen.findByTestId('threat-graph')).toBeInTheDocument()
  await openSection('Facts')
  expect(await screen.findByRole('cell', { name: 'Spearphishing Voice' })).toBeInTheDocument()
})

test('running: shows the live marker and the job panel for its investigate job', async () => {
  mockApi(routes({
    'GET /api/investigations/12/dashboard': dashboard({ state: 'running', finished_at: null }),
    'GET /api/jobs': [job({ params: { target: 'octo tempest' } })],
  }))
  renderPage('?section=matrix')
  expect(await screen.findByText('Investigation progress')).toBeInTheDocument()
  expect(screen.getAllByText('updating live').length).toBeGreaterThan(0)
})

test('failed: red pill and reason, with the partial data still rendered', async () => {
  mockApi(routes({ 'GET /api/investigations/12/dashboard': dashboard({ state: 'failed', failure_reason: 'Claude CLI crashed' }) }))
  renderPage()
  expect(await screen.findByText('Claude CLI crashed')).toBeInTheDocument()
  expect(await screen.findByRole('heading', { name: 'Initial Access' })).toBeInTheDocument()
})

test('unresolved: Resolving target, empty matrix, graph waiting card and no facts card', async () => {
  mockApi(routes({ 'GET /api/investigations/12/dashboard': dashboard({ state: 'running' }, null) }))
  renderPage('?section=matrix')
  expect(await screen.findByRole('heading', { name: 'Resolving target…' })).toBeInTheDocument()
  // The matrix now hides empty tactics; an unresolved investigation shows the empty-state message instead.
  expect(await screen.findByText(/No techniques observed yet/)).toBeInTheDocument()
  await openSection('Relationship graph')
  expect(screen.getByText('Waiting for a resolved target.')).toBeInTheDocument()
  expect(screen.queryByTestId('threat-graph')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /Markdown/ })).not.toBeInTheDocument()
})

test('an unknown investigation shows the error and a way back', async () => {
  mockApi(routes({ 'GET /api/investigations/12/dashboard': new Response(JSON.stringify({ error: 'not found' }), { status: 404 }) }))
  renderPage()
  expect(await screen.findByRole('alert')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Back to investigations' })).toHaveAttribute('href', '/investigations')
})

test('clicking a matrix cell opens the entity panel for that technique', async () => {
  mockApi(routes())
  renderPage()
  await userEvent.click(await screen.findByRole('button', { name: /T1566\.004/ }))
  const dialog = await screen.findByRole('dialog')
  expect(await within(dialog).findByRole('heading', { name: 'Spearphishing Voice' })).toBeInTheDocument()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Close' }))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})

test('a graph node tap opens the entity panel', async () => {
  mockApi(routes())
  renderPage('?section=graph')
  await screen.findByTestId('threat-graph')
  act(() => instances[instances.length - 1].tap('ap--1'))
  expect(await screen.findByRole('dialog')).toBeInTheDocument()
})

test('Expand mounts the fullscreen graph, fetched only then, and Close unmounts it', async () => {
  const fetchMock = mockApi(routes({ 'GET /api/threats/is--1/graph?depth=3&limit=200': GRAPH }))
  const asked = () => fetchMock.mock.calls.some(([url]) => String(url).includes('depth=3'))
  renderPage('?section=graph')
  await screen.findByTestId('threat-graph')
  expect(asked()).toBe(false)
  await userEvent.click(screen.getByRole('button', { name: 'Expand graph' }))
  await waitFor(() => expect(asked()).toBe(true))
  expect(screen.getAllByRole('dialog', { name: 'Relationship graph' })).toHaveLength(1)
  await userEvent.click(screen.getByRole('button', { name: 'Close' }))
  expect(screen.queryByRole('dialog', { name: 'Relationship graph' })).not.toBeInTheDocument()
})

test('Escape closes the entity panel first and the fullscreen graph second', async () => {
  mockApi(routes({ 'GET /api/threats/is--1/graph?depth=3&limit=200': GRAPH }))
  renderPage('?section=graph')
  await screen.findByTestId('threat-graph')
  await userEvent.click(screen.getByRole('button', { name: 'Expand graph' }))
  await screen.findByRole('button', { name: 'Fit' })
  act(() => instances[instances.length - 1].tap('ap--1'))
  expect(await screen.findAllByRole('dialog')).toHaveLength(2)
  await userEvent.keyboard('{Escape}')
  await waitFor(() => expect(screen.getAllByRole('dialog')).toHaveLength(1))
  expect(screen.getByRole('dialog', { name: 'Relationship graph' })).toBeInTheDocument()
  await userEvent.keyboard('{Escape}')
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})

test('a job that ends refreshes the dashboard', async () => {
  let jobs: Job[] = [job({})]
  let calls = 0
  mockApi(routes({
    'GET /api/jobs': () => jobs,
    'GET /api/investigations/12/dashboard': () => {
      calls += 1
      return dashboard({ state: calls > 1 ? 'finished' : 'running' })
    },
  }))
  const { queryClient } = renderPage()
  await screen.findByRole('heading', { name: 'Scattered Spider' })
  expect(await screen.findByText('running')).toBeInTheDocument()
  jobs = [job({ state: 'finished' })]
  await act(() => queryClient.invalidateQueries({ queryKey: ['jobs'] }))
  await waitFor(() => expect(calls).toBeGreaterThan(1))
  expect(await screen.findByText('finished')).toBeInTheDocument()
})

test('missing ATT&CK data shows the setup notice in the matrix section instead of the matrix', async () => {
  mockApi(routes({ 'GET /api/settings': { ...SETTINGS_OK, attack: { present: false, techniques: 0, groups: 0, software: 0 } } }))
  renderPage()
  expect(await screen.findByText('MITRE ATT&CK data is missing')).toBeInTheDocument()
  expect(screen.queryByRole('heading', { name: 'Initial Access' })).not.toBeInTheDocument()
  expect(screen.getByRole('heading', { name: 'Scattered Spider' })).toBeInTheDocument()
})

describe('scope switch', () => {
  const renderAt = (search: string) =>
    renderWithProviders(<DashboardPage />, { route: `/investigations/12/dashboard${search}`, path: '/investigations/:id/dashboard' })
  const asked = (fetchMock: ReturnType<typeof mockApi>, fragment: string) =>
    fetchMock.mock.calls.some(([url]) => String(url).includes(fragment))

  test('defaults to everything and sends no scope', async () => {
    const fetchMock = mockApi(routes())
    renderPage('?section=graph')
    expect(await screen.findByRole('button', { name: 'Everything known' })).toHaveAttribute('aria-pressed', 'true')
    await screen.findByTestId('threat-graph')
    expect(asked(fetchMock, 'scope=')).toBe(false)
  })

  test('?scope=investigation starts scoped and every fetch carries the scope', async () => {
    const fetchMock = mockApi(routes())
    renderAt('?scope=investigation&section=graph')
    expect(await screen.findByRole('button', { name: 'This investigation' })).toHaveAttribute('aria-pressed', 'true')
    await screen.findByTestId('threat-graph')
    await openSection('Facts')
    await screen.findByRole('cell', { name: 'Spearphishing Voice' })
    const scope = encodeURIComponent('investigation:12')
    expect(asked(fetchMock, `/api/investigations/12/dashboard?scope=${scope}`)).toBe(true)
    expect(asked(fetchMock, `/api/threats/is--1/graph?depth=1&scope=${scope}`)).toBe(true)
    expect(asked(fetchMock, `/api/threats/is--1?scope=${scope}`)).toBe(true)
  })

  test('toggling refetches with the scope, and toggling back drops it', async () => {
    const fetchMock = mockApi(routes())
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'This investigation' }))
    await waitFor(() => expect(asked(fetchMock, 'dashboard?scope=investigation%3A12')).toBe(true))
    expect(screen.getByRole('button', { name: 'This investigation' })).toHaveAttribute('aria-pressed', 'true')
    await userEvent.click(screen.getByRole('button', { name: 'Everything known' }))
    expect(screen.getByRole('button', { name: 'Everything known' })).toHaveAttribute('aria-pressed', 'true')
  })

  test('the entity panel and the fullscreen graph carry the scope', async () => {
    const fetchMock = mockApi(routes())
    renderAt('?scope=investigation')
    await userEvent.click(await screen.findByRole('button', { name: /T1566\.004/ }))
    await screen.findByRole('dialog')
    expect(asked(fetchMock, 'threats/ap--1?scope=investigation%3A12')).toBe(true)
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' }))
    await openSection('Relationship graph')
    await userEvent.click(await screen.findByRole('button', { name: 'Expand graph' }))
    await waitFor(() => expect(asked(fetchMock, 'depth=3&limit=200&scope=investigation%3A12')).toBe(true))
  })

  test('an empty scoped matrix with a resolved entity disables "This investigation" with a hint', async () => {
    // Everything has techniques; the scoped fetch has none.
    mockApi(routes({
      'GET /api/investigations/12/dashboard': (_init: RequestInit, url: string) =>
        url.includes('scope=') ? { ...dashboard(), attack_matrix: { tactics: tactics(false) } } : dashboard(),
    }))
    renderAt('?scope=investigation')
    expect(await screen.findByText('This investigation contributed no facts about this entity yet.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'This investigation' })).toBeDisabled()
    // The user's choice is respected: still scoped.
    expect(screen.getByRole('button', { name: 'This investigation' })).toHaveAttribute('aria-pressed', 'true')
  })
})

describe('sidebar', () => {
  const setViewport = (narrow: boolean) => {
    window.matchMedia = vi.fn((query: string) => ({
      matches: narrow && query === '(max-width: 900px)', media: query, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    })) as unknown as typeof window.matchMedia
  }
  afterEach(() => {
    Reflect.deleteProperty(window, 'matchMedia')
  })

  test('lists every section with its count badge', async () => {
    mockApi(routes({
      'GET /api/investigations/12/trace': { cost: null, events: [{ id: 1 }, { id: 2 }] },
    }))
    renderPage()
    const nav = await screen.findByRole('navigation', { name: 'Investigation sections' })
    const item = (name: string) => within(nav).getByRole('button', { name: new RegExp(`^${name}`) })
    expect(within(nav).getAllByRole('button')).toHaveLength(7)
    expect(item('Overview')).toBeInTheDocument()
    expect(item('ATT&CK matrix')).toHaveTextContent('14 tactics · 1 technique')
    await waitFor(() => expect(item('Relationship graph')).toHaveTextContent('2 nodes · 1 edge'))
    expect(item('Known campaigns')).toBeInTheDocument()
    await waitFor(() => expect(item('Facts')).toHaveTextContent('1'))
    await waitFor(() => expect(item('Pipeline trace')).toHaveTextContent('2'))
    expect(item('Documents')).toHaveTextContent('4')
    expect(item('ATT&CK matrix')).toHaveAttribute('aria-current', 'page')
  })

  test('defaults to the overview while the investigation is running or unresolved', async () => {
    mockApi(routes({ 'GET /api/investigations/12/dashboard': dashboard({ state: 'running' }, null) }))
    renderPage()
    expect(await screen.findByRole('button', { name: /^Overview/ })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('heading', { name: 'Quick actions' })).toBeInTheDocument()
  })

  test('clicking a section swaps the pane and keeps the scope', async () => {
    mockApi(routes())
    renderPage('?scope=investigation')
    await screen.findByRole('heading', { name: 'Initial Access' })
    await openSection('Relationship graph')
    expect(await screen.findByTestId('threat-graph')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Initial Access' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Relationship graph/ })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('button', { name: 'This investigation' })).toHaveAttribute('aria-pressed', 'true')
    await openSection('Pipeline trace')
    expect(await screen.findByRole('heading', { name: 'Pipeline trace' })).toBeInTheDocument()
  })

  test('?section=graph lands on the graph pane', async () => {
    mockApi(routes())
    renderPage('?section=graph')
    expect(await screen.findByTestId('threat-graph')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Relationship graph/ })).toHaveAttribute('aria-current', 'page')
  })

  test('an unknown ?section= falls back to the default', async () => {
    mockApi(routes())
    renderPage('?section=nope')
    expect(await screen.findByRole('heading', { name: 'Initial Access' })).toBeInTheDocument()
  })

  test('is a sidebar on wide viewports and a pill bar on narrow ones', async () => {
    setViewport(false)
    mockApi(routes())
    const wide = renderPage()
    expect(await screen.findByRole('navigation', { name: 'Investigation sections' })).toHaveAttribute('data-layout', 'sidebar')
    wide.unmount()
    setViewport(true)
    renderPage()
    expect(await screen.findByRole('navigation', { name: 'Investigation sections' })).toHaveAttribute('data-layout', 'pills')
  })
})
