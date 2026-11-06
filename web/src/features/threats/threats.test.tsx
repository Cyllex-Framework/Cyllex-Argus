import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Link } from 'react-router-dom'
import { ThreatsPage } from './ThreatsPage'
import { ThreatProfilePage } from './ThreatProfilePage'
import { mockApi, renderWithProviders } from '../../test/utils'

const SPIDER = 'intrusion-set--1'
const ref = (id: string, name: string, stix_type: string, external_id: string | null = null) => ({
  id, name, stix_type, external_id, attack: true, label: external_id ? `${name} (${external_id})` : name,
})
const citation = (quote: string, publisher = 'Mandiant', location: string | null = 'https://mandiant.example/r') => ({
  claim_id: 1, quote, quote_status: 'verified', polarity: 'asserts', document_title: 'Deep dive', location, publisher, published_at: '2025-01-10',
})
const PROFILE = {
  entity: ref(SPIDER, 'Scattered Spider', 'intrusion-set'),
  aliases: [{ alias: 'UNC3944', origin: 'attack' }, { alias: 'PROJECT-FALCON', origin: 'document' }],
  facts: [
    { subject: ref(SPIDER, 'Scattered Spider', 'intrusion-set'), predicate: 'uses', object: ref('ap--1', 'Spearphishing Voice', 'attack-pattern', 'T1566.004'),
      status: 'corroborated', confidence: 84, admiralty: 'B2', first_seen: '2023-06-01', last_seen: '2025-01-10',
      citations: [citation('called the IT help desk <img src=x onerror=alert(1)>'), citation('second quote', 'Microsoft')], source_count: 2 },
    { subject: ref(SPIDER, 'Scattered Spider', 'intrusion-set'), predicate: 'targets', object: ref('id--1', 'retail', 'identity'),
      status: 'single-source', confidence: 30, admiralty: 'F3', first_seen: null, last_seen: null,
      citations: [citation('retail victims', 'News', 'memo.txt')], source_count: 1 },
  ],
}

test('threat search lists results and filters by query', async () => {
  const fetchMock = mockApi({
    'GET /api/threats': [{ id: SPIDER, stix_type: 'intrusion-set', name: 'Scattered Spider', external_id: null, label: 'Scattered Spider', facts: 2, attack: true }],
  })
  renderWithProviders(<ThreatsPage />)
  expect(await screen.findByRole('link', { name: 'Scattered Spider' })).toHaveAttribute('href', `/threats/${SPIDER}`)
  await userEvent.type(screen.getByLabelText('Search threats'), 'octo')
  await screen.findByRole('link', { name: 'Scattered Spider' })
  expect(fetchMock.mock.calls.some(([url]) => String(url).includes('q=octo'))).toBe(true)
})

test('threat search empty state', async () => {
  mockApi({ 'GET /api/threats': [] })
  renderWithProviders(<ThreatsPage />)
  expect(await screen.findByText(/No threats with facts yet/)).toBeInTheDocument()
})

test('profile shows aliases, facts, filters, citations and exports; hostile text stays text', async () => {
  mockApi({ [`GET /api/threats/${SPIDER}`]: PROFILE })
  renderWithProviders(<ThreatProfilePage />, { route: `/threats/${SPIDER}`, path: '/threats/:id' })
  expect(await screen.findByRole('heading', { name: 'Scattered Spider' })).toBeInTheDocument()
  expect(screen.getByText('UNC3944')).toBeInTheDocument()
  expect(screen.getByText('PROJECT-FALCON')).toHaveAttribute('title', expect.stringContaining('document'))
  await userEvent.click(await screen.findByRole('button', { name: 'Show table' }))
  const table = await screen.findByRole('table')
  expect(within(table).getByText('Spearphishing Voice (T1566.004)')).toBeInTheDocument()
  expect(within(table).getByText('B2')).toBeInTheDocument()

  await userEvent.selectOptions(screen.getByLabelText('Filter by status'), 'corroborated')
  expect(within(table).queryByText('retail')).not.toBeInTheDocument()
  await userEvent.selectOptions(screen.getByLabelText('Filter by status'), '')

  await userEvent.click(within(table).getByText('Spearphishing Voice (T1566.004)'))
  const panel = screen.getByRole('region', { name: 'Citations' })
  expect(within(panel).getByText(/called the IT help desk <img src=x onerror=alert\(1\)>/)).toBeInTheDocument()
  expect(document.querySelector('img[src="x"]')).toBeNull()
  expect(within(panel).getAllByRole('link')[0]).toHaveAttribute('href', 'https://mandiant.example/r')

  expect(screen.getByRole('button', { name: 'Markdown' })).toBeEnabled()
  expect(screen.getByRole('button', { name: 'Markdown + AI summary' })).toHaveAttribute('title', expect.stringContaining('Claude'))
  expect(screen.getByRole('button', { name: 'STIX 2.1' })).toBeEnabled()
  expect(document.querySelector('a[href*="/api/"]')).toBeNull() // a plain link could not send the token header
})

describe('exports', () => {
  let saved: string[] = []

  beforeEach(() => {
    saved = []
    localStorage.setItem('argus.token', 'tok-1')
    URL.createObjectURL = vi.fn(() => 'blob:argus/1')
    URL.revokeObjectURL = vi.fn()
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      saved.push(this.download)
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    localStorage.clear()
  })

  const file = (body: string, name: string) =>
    new Response(body, { headers: { 'Content-Disposition': `attachment; filename="${name}"` } })

  test.each([
    ['Markdown', '?format=markdown', 'Scattered_Spider.md'],
    ['Markdown + AI summary', '?format=markdown&summary=1', 'Scattered_Spider.md'],
    ['STIX 2.1', '?format=stix', 'Scattered_Spider.stix.json'],
  ])('%s fetches the export with the token and saves it under the server name', async (label, query, name) => {
    const fetchMock = mockApi({
      [`GET /api/threats/${SPIDER}`]: PROFILE,
      'GET /api/ttp-templates': [], 'GET /api/jobs': [],
      [`GET /api/threats/${SPIDER}/export${query}`]: file('content', name),
    })
    renderWithProviders(<ThreatProfilePage />, { route: `/threats/${SPIDER}`, path: '/threats/:id' })
    await userEvent.click(await screen.findByRole('button', { name: label }))
    await waitFor(() => expect(saved).toEqual([name]))
    const call = fetchMock.mock.calls.find(([url]) => String(url).includes('/export'))!
    expect(String(call[0])).toBe(`/api/threats/${SPIDER}/export${query}`)
    expect(new Headers(call[1]?.headers).get('X-Argus-Token')).toBe('tok-1')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  test('an export shows it is busy until the file arrives', async () => {
    let deliver: (response: Response) => void = () => {}
    mockApi({
      [`GET /api/threats/${SPIDER}`]: PROFILE,
      'GET /api/ttp-templates': [], 'GET /api/jobs': [],
      [`GET /api/threats/${SPIDER}/export?format=markdown&summary=1`]: () => new Promise<Response>((resolve) => { deliver = resolve }),
    })
    renderWithProviders(<ThreatProfilePage />, { route: `/threats/${SPIDER}`, path: '/threats/:id' })
    const button = await screen.findByRole('button', { name: 'Markdown + AI summary' })
    await userEvent.click(button)
    expect(button).toBeDisabled()
    expect(button).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByRole('status')).toHaveTextContent(/Preparing Markdown \+ AI summary/)
    expect(screen.getByRole('button', { name: 'STIX 2.1' })).toBeEnabled() // the others do not wait for it
    deliver(file('# Spider', 'Scattered_Spider.md'))
    await waitFor(() => expect(button).toBeEnabled())
    expect(button).not.toHaveAttribute('aria-busy')
    expect(saved).toEqual(['Scattered_Spider.md'])
  })

  test('a failed export shows the server error inline and saves nothing', async () => {
    mockApi({
      [`GET /api/threats/${SPIDER}`]: PROFILE,
      'GET /api/ttp-templates': [], 'GET /api/jobs': [],
      [`GET /api/threats/${SPIDER}/export?format=stix`]: new Response(JSON.stringify({ error: 'unknown threat' }), { status: 404 }),
      [`GET /api/threats/${SPIDER}/export?format=markdown`]: file('# Spider', 'Scattered_Spider.md'),
    })
    renderWithProviders(<ThreatProfilePage />, { route: `/threats/${SPIDER}`, path: '/threats/:id' })
    await userEvent.click(await screen.findByRole('button', { name: 'STIX 2.1' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('STIX 2.1 export failed: unknown threat')
    expect(saved).toEqual([])
    await userEvent.click(screen.getByRole('button', { name: 'Markdown' })) // a later success clears the error
    await waitFor(() => expect(saved).toEqual(['Scattered_Spider.md']))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})

test('profile without facts shows an empty state', async () => {
  mockApi({ [`GET /api/threats/${SPIDER}`]: { ...PROFILE, facts: [] } })
  renderWithProviders(<ThreatProfilePage />, { route: `/threats/${SPIDER}`, path: '/threats/:id' })
  expect(await screen.findByText(/No facts yet/)).toBeInTheDocument()
})

test('unknown threat shows the API error', async () => {
  mockApi({ 'GET /api/threats/nope': new Response(JSON.stringify({ error: 'unknown threat' }), { status: 404 }) })
  renderWithProviders(<ThreatProfilePage />, { route: '/threats/nope', path: '/threats/:id' })
  expect(await screen.findByText('unknown threat')).toBeInTheDocument()
})

const day = (year: number, month: number, date: number) => new Date(year, month - 1, date).toLocaleDateString()

test('the relation filter narrows the facts and the seen column shows local dates', async () => {
  mockApi({ [`GET /api/threats/${SPIDER}`]: PROFILE })
  renderWithProviders(<ThreatProfilePage />, { route: `/threats/${SPIDER}`, path: '/threats/:id' })
  await userEvent.click(await screen.findByRole('button', { name: 'Show table' }))
  const table = await screen.findByRole('table')
  expect(within(table).getByText(`${day(2023, 6, 1)} .. ${day(2025, 1, 10)}`)).toBeInTheDocument()
  const relation = screen.getByLabelText('Filter by relation')
  expect(within(relation).getAllByRole('option').map((o) => o.textContent)).toEqual(['All relations', 'targets', 'uses'])
  await userEvent.selectOptions(relation, 'targets')
  expect(within(table).getByText('retail')).toBeInTheDocument()
  expect(within(table).queryByText('Spearphishing Voice (T1566.004)')).not.toBeInTheDocument()
})

test('an incoming fact names the other entity and marks the relation as inbound', async () => {
  const campaign = ref('campaign--1', 'Operation Ghost', 'campaign')
  const incoming = { ...PROFILE.facts[0], subject: campaign, predicate: 'attributed-to', object: PROFILE.entity, first_seen: '2024-05-02', last_seen: '2024-05-02' }
  mockApi({ [`GET /api/threats/${SPIDER}`]: { ...PROFILE, facts: [incoming] } })
  renderWithProviders(<ThreatProfilePage />, { route: `/threats/${SPIDER}`, path: '/threats/:id' })
  await userEvent.click(await screen.findByRole('button', { name: 'Show table' }))
  const table = await screen.findByRole('table')
  expect(within(table).getByText('attributed-to (by)')).toBeInTheDocument()
  expect(within(table).getByText('Operation Ghost')).toBeInTheDocument()
  expect(within(table).getByText(day(2024, 5, 2))).toBeInTheDocument()
})

test('a fact row can be selected from the keyboard', async () => {
  mockApi({ [`GET /api/threats/${SPIDER}`]: PROFILE })
  renderWithProviders(<ThreatProfilePage />, { route: `/threats/${SPIDER}`, path: '/threats/:id' })
  const panel = await screen.findByRole('region', { name: 'Citations' })
  expect(within(panel).getByText(/Select a fact/)).toBeInTheDocument()
  await userEvent.click(await screen.findByRole('button', { name: 'Show table' }))
  const row = within(await screen.findByRole('table')).getByText('retail').closest('tr')!
  row.focus()
  await userEvent.keyboard('{Enter}')
  expect(row).toHaveAttribute('aria-selected', 'true')
  expect(within(panel).getByText(/retail victims/)).toBeInTheDocument()
})

test('citations render a local file as text, mark refuting and approximate quotes, and format the date', async () => {
  const refuting = { ...citation('not attributed', 'Wired', 'javascript:alert(1)'), polarity: 'refutes', quote_status: 'verified_fuzzy', published_at: null }
  const fact = { ...PROFILE.facts[1], citations: [citation('retail victims', 'News', 'memo.txt'), refuting] }
  mockApi({ [`GET /api/threats/${SPIDER}`]: { ...PROFILE, facts: [fact] } })
  renderWithProviders(<ThreatProfilePage />, { route: `/threats/${SPIDER}`, path: '/threats/:id' })
  await userEvent.click(await screen.findByRole('button', { name: 'Show table' }))
  await userEvent.click(within(await screen.findByRole('table')).getByText('retail'))
  const panel = screen.getByRole('region', { name: 'Citations' })
  expect(within(panel).queryAllByRole('link')).toHaveLength(0)
  expect(within(panel).getByText('memo.txt')).toBeInTheDocument()
  expect(within(panel).getByText('javascript:alert(1)')).toBeInTheDocument()
  expect(within(panel).getByText(day(2025, 1, 10))).toBeInTheDocument()
  expect(within(panel).getByText('undated')).toBeInTheDocument()
  expect(within(panel).getByText('refutes')).toBeInTheDocument()
  expect(within(panel).getByText('approximate match')).toBeInTheDocument()
})

test('the profile renders the graph slot for the current threat', async () => {
  mockApi({ [`GET /api/threats/${SPIDER}`]: PROFILE })
  renderWithProviders(<ThreatProfilePage graphSlot={(id) => <p>graph for {id}</p>} />, { route: `/threats/${SPIDER}`, path: '/threats/:id' })
  expect(await screen.findByText(`graph for ${SPIDER}`)).toBeInTheDocument()
})

test('search keeps the previous results on screen, dimmed, while the next query is pending', async () => {
  const listing = (id: string, label: string) => [{ id, stix_type: 'intrusion-set', name: label, external_id: null, label, facts: 2, attack: true }]
  let release!: (response: Response) => void
  const next = new Promise<Response>((resolve) => { release = resolve })
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    if (String(input).includes('q=octo')) return next
    return Promise.resolve(new Response(JSON.stringify(listing(SPIDER, 'Scattered Spider')), { status: 200 }))
  })
  vi.stubGlobal('fetch', fetchMock)
  renderWithProviders(<ThreatsPage />)
  expect(screen.getByText('Loading...')).toBeInTheDocument()
  const first = await screen.findByRole('link', { name: 'Scattered Spider' })
  const results = first.closest('[aria-busy]')!
  expect(results).toHaveAttribute('aria-busy', 'false')
  expect(results).not.toHaveClass('opacity-60')

  await userEvent.type(screen.getByLabelText('Search threats'), 'octo')
  await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).includes('q=octo'))).toBe(true))
  expect(screen.getByRole('link', { name: 'Scattered Spider' })).toBeInTheDocument()
  expect(screen.queryByText('Loading...')).not.toBeInTheDocument()
  await waitFor(() => expect(results).toHaveClass('opacity-60'))
  expect(results).toHaveAttribute('aria-busy', 'true')

  release(new Response(JSON.stringify(listing('intrusion-set--2', 'Octo Tempest')), { status: 200 }))
  expect(await screen.findByRole('link', { name: 'Octo Tempest' })).toBeInTheDocument()
  expect(screen.queryByRole('link', { name: 'Scattered Spider' })).not.toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Octo Tempest' }).closest('[aria-busy]')).not.toHaveClass('opacity-60')
})

test('moving to another threat resets the fact selection and the filters', async () => {
  const OTHER = 'intrusion-set--2'
  const other = ref(OTHER, 'Octo Tempest', 'intrusion-set')
  // The first fact links both threats, so it is present in both profiles; the second fact only in the new one.
  const shared = { ...PROFILE.facts[0], subject: PROFILE.entity, object: other }
  const OTHER_PROFILE = {
    entity: other,
    aliases: [],
    facts: [shared, { ...PROFILE.facts[1], subject: other, object: ref('id--2', 'finance', 'identity') }],
  }
  mockApi({
    [`GET /api/threats/${SPIDER}`]: { ...PROFILE, facts: [shared, PROFILE.facts[1]] },
    [`GET /api/threats/${OTHER}`]: OTHER_PROFILE,
  })
  const { queryClient } = renderWithProviders(
    <>
      <Link to={`/threats/${OTHER}`}>go to other</Link>
      <ThreatProfilePage />
    </>,
    { route: `/threats/${SPIDER}`, path: '/threats/:id' },
  )
  // A threat visited before is served from the cache, so the page never falls back to "Loading..." between the two.
  queryClient.setQueryData(['threat', OTHER], OTHER_PROFILE)
  await userEvent.click(await screen.findByRole('button', { name: 'Show table' }))
  const table = await screen.findByRole('table')
  await userEvent.selectOptions(screen.getByLabelText('Filter by relation'), 'uses')
  await userEvent.selectOptions(screen.getByLabelText('Filter by status'), 'corroborated')
  await userEvent.click(within(table).getByText('Octo Tempest'))
  const panel = screen.getByRole('region', { name: 'Citations' })
  expect(within(panel).getByText(/called the IT help desk/)).toBeInTheDocument()

  await userEvent.click(screen.getByRole('link', { name: 'go to other' }))
  expect(await screen.findByRole('heading', { name: 'Octo Tempest' })).toBeInTheDocument()
  await userEvent.click(await screen.findByRole('button', { name: 'Show table' }))
  expect(screen.getByLabelText('Filter by relation')).toHaveValue('')
  expect(screen.getByLabelText('Filter by status')).toHaveValue('')
  expect(within(screen.getByRole('table')).getAllByRole('row').filter((row) => row.getAttribute('aria-selected') === 'true')).toHaveLength(0)
  expect(within(screen.getByRole('region', { name: 'Citations' })).getByText(/Select a fact/)).toBeInTheDocument()
  expect(within(screen.getByRole('table')).getByText('finance')).toBeInTheDocument()
})
