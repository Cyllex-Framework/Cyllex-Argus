import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { act } from 'react'
import { DashboardPage } from './dashboard/DashboardPage'
import { JobPanel } from './investigations/JobPanel'
import { SourcesPage } from './sources/SourcesPage'
import { SettingsPage } from './settings/SettingsPage'
import { LLM_SETTINGS as LLM, MockEventStream, mockApi, renderWithProviders } from '../test/utils'

const OVERVIEW = {
  counts: { threats: 3, documents: { validated: 5, failed: 1 }, assessments: { corroborated: 4, contested: 1, 'single-source': 7 }, investigations: 2 },
  recent_investigations: [{ id: 7, target: 'Scattered Spider', state: 'finished', started_at: '2026-09-29T10:00:00+00:00', finished_at: null, collected: true, stage_counts: { validated: 2 } }],
  unrated_publishers: [{ id: 1, name: 'Mandiant' }],
}

test('dashboard shows stat tiles, recent investigations and sources to rate', async () => {
  mockApi({ 'GET /api/overview': OVERVIEW })
  renderWithProviders(<DashboardPage />)
  expect(await screen.findByText('Threats with facts')).toBeInTheDocument()
  const tile = screen.getByText('Corroborated facts').closest('.stat-card') as HTMLElement
  expect(within(tile).getByText('4')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Scattered Spider' })).toHaveAttribute('href', '/investigations/7/dashboard')
  expect(screen.getByRole('link', { name: 'Mandiant' })).toHaveAttribute('href', '/sources')
})

test('dashboard shows a dash instead of "Invalid Date" for an unreadable start time', async () => {
  const [investigation] = OVERVIEW.recent_investigations
  mockApi({ 'GET /api/overview': { ...OVERVIEW, recent_investigations: [{ ...investigation, started_at: 'garbage' }] } })
  renderWithProviders(<DashboardPage />)
  const row = (await screen.findByRole('link', { name: 'Scattered Spider' })).closest('tr') as HTMLElement
  expect(within(row).getByText('-')).toBeInTheDocument()
  expect(row).not.toHaveTextContent('Invalid Date')
})

test('dashboard empty state', async () => {
  mockApi({ 'GET /api/overview': { ...OVERVIEW, recent_investigations: [], unrated_publishers: [] } })
  renderWithProviders(<DashboardPage />)
  expect(await screen.findByText(/No investigations yet/)).toBeInTheDocument()
})

const setup = (present: boolean, found: boolean) => ({
  attack: { present, techniques: 0, groups: 0, software: 0 }, claude: { found }, config: {}, home: 'C:/argus',
  llm: LLM,
})

test('dashboard guides a fresh install: a Finish setup notice that runs the ATT&CK update from the first screen', async () => {
  MockEventStream.instances = []
  const fetchMock = mockApi({
    'GET /api/overview': OVERVIEW, 'GET /api/settings': setup(false, false), 'GET /api/jobs': [],
    'POST /api/jobs': { id: 'a1', kind: 'attack_update', params: {}, state: 'queued', created_at: '', started_at: null, finished_at: null, message: null, result: null, events: 0 },
  })
  renderWithProviders(<DashboardPage />)
  const notice = await screen.findByRole('region', { name: 'Finish setup' })
  expect(notice).toHaveTextContent('investigate threats or ingest documents')
  expect(notice).toHaveTextContent('Claude Code CLI not found')
  await userEvent.click(within(notice).getByRole('button', { name: 'Update ATT&CK' }))
  await waitFor(() => expect(fetchMock.mock.calls.some(([url, init]) => String(url) === '/api/jobs' && init?.method === 'POST')).toBe(true))
  expect(await within(notice).findByText('ATT&CK update')).toBeInTheDocument()
})

test('dashboard shows no setup notice once everything is in place', async () => {
  const fetchMock = mockApi({ 'GET /api/overview': OVERVIEW, 'GET /api/settings': setup(true, true), 'GET /api/jobs': [] })
  renderWithProviders(<DashboardPage />)
  await screen.findByText('Threats with facts')
  await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url) === '/api/settings')).toBe(true))
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)))
  expect(screen.queryByRole('region', { name: 'Finish setup' })).not.toBeInTheDocument()
})

const MANDIANT = { id: 1, name: 'Mandiant', domain: 'mandiant.com', reliability: 'F', documents: 2 }
const recomputeJob = (id: string, state = 'queued', result: Record<string, unknown> | null = null, message: string | null = null) => ({
  id, kind: 'recompute', params: {}, state, created_at: '', started_at: null, finished_at: null, message, result, events: 0,
})
const updated = (reliability: string, job = recomputeJob('r1')) => ({ id: 1, name: 'Mandiant', domain: 'mandiant.com', reliability, job })

test('sources: changing reliability saves it, then follows the recompute job until it finishes', async () => {
  MockEventStream.instances = []
  let sources = [MANDIANT]
  const fetchMock = mockApi({
    'GET /api/sources': () => sources,
    'GET /api/jobs': [],
    'PUT /api/sources/1': () => {
      sources = [{ ...MANDIANT, reliability: 'B' }]
      return updated('B')
    },
  })
  renderWithProviders(<SourcesPage />)
  const select = await screen.findByLabelText('Reliability of Mandiant')
  await userEvent.selectOptions(select, 'B')
  expect(await screen.findByRole('status')).toHaveTextContent('Mandiant set to B; recomputing confidences…')
  await waitFor(() => expect(select).toHaveValue('B')) // the new value shows at once, before the recompute ends
  const put = fetchMock.mock.calls.find(([, init]) => init?.method === 'PUT')
  expect(JSON.parse(String(put?.[1]?.body))).toEqual({ reliability: 'B' })
  const source = MockEventStream.instances[0]
  expect(source.url).toBe('/api/jobs/r1/events')
  const loadsBefore = fetchMock.mock.calls.filter(([url]) => String(url) === '/api/sources').length
  await act(() => source.emitEnd(recomputeJob('r1', 'finished', { state: 'finished', recomputed: true }, 'Recomputed 4 assessment(s).')))
  expect(await screen.findByRole('status')).toHaveTextContent('Mandiant set to B; confidences recomputed.')
  // The end of the job refreshes the data, so every page shows the new confidences.
  await waitFor(() => expect(fetchMock.mock.calls.filter(([url]) => String(url) === '/api/sources').length).toBeGreaterThan(loadsBefore))
})

test('sources: the select shows the saved value at once, without waiting for the list to be fetched again', async () => {
  MockEventStream.instances = []
  let release: () => void = () => {}
  const slowList = new Promise<void>((resolve) => { release = resolve })
  let loads = 0
  const fetchMock = mockApi({ 'GET /api/jobs': [], 'PUT /api/sources/1': updated('B') })
  const routes = fetchMock.getMockImplementation()!
  fetchMock.mockImplementation(async (input, init) => {
    if (String(input) === '/api/sources' && loads++ > 0) await slowList // every refetch hangs, like one cut short
    return String(input) === '/api/sources' ? new Response(JSON.stringify([MANDIANT]), { status: 200 }) : routes(input, init)
  })
  renderWithProviders(<SourcesPage />)
  const select = await screen.findByLabelText('Reliability of Mandiant')
  await userEvent.selectOptions(select, 'B')
  await screen.findByText(/Mandiant set to B/)
  expect(select).toHaveValue('B')
  release()
})

test('sources: a failed change shows the server error and drops the earlier notice', async () => {
  MockEventStream.instances = []
  let calls = 0
  mockApi({
    'GET /api/sources': [MANDIANT],
    'GET /api/jobs': [],
    'PUT /api/sources/1': () => {
      calls += 1
      return calls === 1
        ? updated('B')
        : new Response(JSON.stringify({ error: 'unknown source' }), { status: 404, headers: { 'Content-Type': 'application/json' } })
    },
  })
  renderWithProviders(<SourcesPage />)
  const select = await screen.findByLabelText('Reliability of Mandiant')
  await userEvent.selectOptions(select, 'B')
  await act(() => MockEventStream.instances[0].emitEnd(recomputeJob('r1', 'finished', { recomputed: true })))
  expect(await screen.findByText('Mandiant set to B; confidences recomputed.')).toBeInTheDocument()
  await waitFor(() => expect(select).toBeEnabled())
  await userEvent.selectOptions(select, 'C')
  expect(await screen.findByRole('alert')).toHaveTextContent('unknown source')
  expect(screen.getByRole('status')).toBeEmptyDOMElement()
})

test('sources: says so when the recompute found no ATT&CK data', async () => {
  MockEventStream.instances = []
  mockApi({ 'GET /api/sources': [MANDIANT], 'GET /api/jobs': [], 'PUT /api/sources/1': updated('B') })
  renderWithProviders(<SourcesPage />)
  await userEvent.selectOptions(await screen.findByLabelText('Reliability of Mandiant'), 'B')
  await screen.findByText(/recomputing confidences/)
  await act(() => MockEventStream.instances[0].emitEnd(recomputeJob('r1', 'finished', { recomputed: false }, 'Confidences were not recomputed: ATT&CK data is missing (x).')))
  expect(await screen.findByRole('status')).toHaveTextContent(
    'Mandiant set to B. Confidences were not recomputed (ATT&CK data missing).',
  )
})

test('sources: a failed recompute shows its message', async () => {
  MockEventStream.instances = []
  mockApi({ 'GET /api/sources': [MANDIANT], 'GET /api/jobs': [], 'PUT /api/sources/1': updated('B') })
  renderWithProviders(<SourcesPage />)
  await userEvent.selectOptions(await screen.findByLabelText('Reliability of Mandiant'), 'B')
  await screen.findByText(/recomputing confidences/)
  await act(() => MockEventStream.instances[0].emitEnd(recomputeJob('r1', 'failed', null, 'OperationalError: database is locked')))
  expect(await screen.findByRole('status')).toHaveTextContent(
    'Mandiant set to B, but recomputing confidences failed: OperationalError: database is locked',
  )
})

test('sources: a recompute found in the job list is followed after a navigation, and its result stays', async () => {
  MockEventStream.instances = []
  let jobs = [recomputeJob('r7', 'running')]
  mockApi({ 'GET /api/sources': [MANDIANT], 'GET /api/jobs': () => jobs })
  renderWithProviders(<SourcesPage />)
  expect(await screen.findByRole('status')).toHaveTextContent('Recomputing confidences…')
  expect(MockEventStream.instances[0].url).toBe('/api/jobs/r7/events')
  jobs = [recomputeJob('r7', 'finished', { recomputed: true })]
  await act(() => MockEventStream.instances[0].emitEnd(jobs[0]))
  expect(await screen.findByRole('status')).toHaveTextContent('Confidences recomputed.')
})

test('sources: an old finished recompute is not announced on arrival', async () => {
  MockEventStream.instances = []
  mockApi({ 'GET /api/sources': [MANDIANT], 'GET /api/jobs': [recomputeJob('r7', 'finished', { recomputed: true })] })
  const { queryClient } = renderWithProviders(<SourcesPage />)
  await screen.findByLabelText('Reliability of Mandiant')
  await waitFor(() => expect(queryClient.getQueryData(['jobs'])).toBeDefined())
  expect(screen.getByRole('status')).toBeEmptyDOMElement()
  expect(MockEventStream.instances).toHaveLength(0)
})

test('sources: the status region exists before any change so screen readers announce the notice', async () => {
  mockApi({ 'GET /api/sources': [{ id: 1, name: 'Mandiant', domain: null, reliability: 'F', documents: 2 }] })
  renderWithProviders(<SourcesPage />)
  await screen.findByLabelText('Reliability of Mandiant')
  expect(screen.getByRole('status')).toBeEmptyDOMElement()
})

test('settings shows ATT&CK and Claude status and runs an update job with live progress', async () => {
  MockEventStream.instances = []
  mockApi({
    'GET /api/settings': { attack: { present: false, techniques: 0, groups: 0, software: 0 }, claude: { found: false }, config: { limits: { max_docs: 25 } }, home: 'C:/argus', llm: LLM },
    'POST /api/jobs': { id: 'j9', kind: 'attack_update', params: {}, state: 'queued', created_at: '', started_at: null, finished_at: null, message: null, result: null, events: 0 },
  })
  renderWithProviders(<SettingsPage />)
  expect(await screen.findByText(/ATT&CK data is missing/)).toBeInTheDocument()
  expect(screen.getByText(/Claude Code CLI not found/)).toBeInTheDocument()
  expect(screen.getByText('C:/argus')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Update ATT&CK' }))
  // The button now opens a confirm dialog that warns about the outbound download; the job fires
  // only once the operator confirms.
  await userEvent.click(await screen.findByRole('button', { name: 'Download & update' }))
  const source = MockEventStream.instances[0]
  await act(() => source.emit({ seq: 1, time: '2026-09-29T10:00:00+00:00', message: 'Downloading MITRE ATT&CK Enterprise' }))
  expect(await screen.findByText('Downloading MITRE ATT&CK Enterprise')).toBeInTheDocument()
  await act(() => source.emitEnd({ id: 'j9', kind: 'attack_update', params: {}, state: 'finished', message: 'ATT&CK loaded: 2 techniques', result: null, events: 1 }))
  expect(await screen.findByText('ATT&CK loaded: 2 techniques')).toBeInTheDocument()
})

test.each([
  ['a duplicate job', 'an identical job is already queued or running'],
  ['missing ATT&CK data', 'ATT&CK data is missing; run the ATT&CK update first'],
])('settings shows the server error text when starting the update is refused (409, %s)', async (_case, detail) => {
  MockEventStream.instances = []
  mockApi({
    'GET /api/settings': { attack: { present: true, techniques: 10, groups: 2, software: 3 }, claude: { found: true }, config: {}, home: 'C:/argus', llm: LLM },
    'POST /api/jobs': new Response(JSON.stringify({ error: detail }), { status: 409, headers: { 'Content-Type': 'application/json' } }),
  })
  renderWithProviders(<SettingsPage />)
  await userEvent.click(await screen.findByRole('button', { name: 'Update ATT&CK' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Download & update' }))
  expect(await screen.findByRole('alert')).toHaveTextContent(detail)
  expect(MockEventStream.instances).toHaveLength(0)
})

test('job panel shows a paused investigation message and its result summary', async () => {
  MockEventStream.instances = []
  mockApi({})
  renderWithProviders(<JobPanel jobId="j1" title="Investigation" />)
  const source = MockEventStream.instances[0]
  expect(screen.getByText('Waiting for the job to start...')).toBeInTheDocument()
  await act(() => source.emit({ seq: 1, time: '2026-09-29T10:00:00+00:00', message: 'Collected 3 candidate(s)' }))
  expect(screen.getByText('Collected 3 candidate(s)')).toBeInTheDocument()
  await act(() => source.emitEnd({
    id: 'j1', kind: 'investigate', params: {}, state: 'paused', message: 'Paused: rate limit. Use Resume to continue.',
    result: { investigation_id: 7, stage_counts: { validated: 2, failed: 1 } }, events: 1,
  }))
  expect(screen.getByText('paused')).toBeInTheDocument()
  expect(screen.getByText('Paused: rate limit. Use Resume to continue.')).toBeInTheDocument()
  expect(screen.getByText('validated: 2 · failed: 1')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Open investigation #7' })).toHaveAttribute('href', '/investigations/7/dashboard')
})

test('job panel shows queued until the first event arrives, then running', async () => {
  MockEventStream.instances = []
  mockApi({})
  renderWithProviders(<JobPanel jobId="j1" />)
  expect(screen.getByText('queued')).toBeInTheDocument()
  await act(() => MockEventStream.instances[0].emit({ seq: 1, time: '2026-09-29T10:00:00+00:00', message: 'Investigating x' }))
  expect(screen.getByText('running')).toBeInTheDocument()
  expect(screen.queryByText('queued')).not.toBeInTheDocument()
})

test.each([
  ['a null investigation id', { investigation_id: null, stage_counts: { validated: 1 } }, false, 'validated: 1'],
  ['a string investigation id', { investigation_id: '7', stage_counts: { validated: 1 } }, false, 'validated: 1'],
  ['a string stage_counts', { investigation_id: 7, stage_counts: 'x' }, true, null],
  ['an array stage_counts', { investigation_id: 7, stage_counts: ['validated'] }, true, null],
  ['a null stage_counts', { investigation_id: 7, stage_counts: null }, true, null],
  ['both malformed', { investigation_id: null, stage_counts: 'x' }, false, null],
])('job panel only trusts a well-formed result: %s', async (_case, result, link, summary) => {
  MockEventStream.instances = []
  mockApi({})
  renderWithProviders(<JobPanel jobId="j1" />)
  await act(() => MockEventStream.instances[0].emitEnd({
    id: 'j1', kind: 'investigate', params: {}, state: 'finished', message: 'Done', result, events: 0,
  }))
  expect(screen.getByText('Done')).toBeInTheDocument()
  if (link) expect(screen.getByRole('link', { name: 'Open investigation #7' })).toBeInTheDocument()
  else expect(screen.queryByRole('link')).not.toBeInTheDocument()
  if (summary) expect(screen.getByText(summary)).toBeInTheDocument()
  // The old guard rendered Object.entries('x') / Object.entries(['validated']) as "0: x" / "0: validated".
  expect(screen.queryByText(/^0: /)).not.toBeInTheDocument()
  if (!summary) expect(screen.queryByText(/validated: \d/)).not.toBeInTheDocument()
})

test('job panel says so when the job is no longer available (null end payload)', async () => {
  MockEventStream.instances = []
  mockApi({})
  renderWithProviders(<JobPanel jobId="gone" />)
  expect(screen.getByText('Waiting for the job to start...')).toBeInTheDocument()
  await act(() => MockEventStream.instances[0].emitEnd(null))
  expect(screen.getByText('unknown')).toBeInTheDocument()
  expect(screen.getByText('This job is no longer available.')).toBeInTheDocument()
  expect(screen.queryByText('Waiting for the job to start...')).not.toBeInTheDocument()
})

test('job panel wraps a long final message', async () => {
  MockEventStream.instances = []
  mockApi({})
  renderWithProviders(<JobPanel jobId="j1" />)
  await act(() => MockEventStream.instances[0].emitEnd({
    id: 'j1', kind: 'attack_update', params: {}, state: 'failed', message: 'x'.repeat(300), result: null, events: 0,
  }))
  expect(screen.getByText('x'.repeat(300))).toHaveClass('break-words')
})

test('job panel renders nothing without a job id', () => {
  const { container } = renderWithProviders(<JobPanel jobId={null} />)
  expect(container).toBeEmptyDOMElement()
})

test('job panel says the progress was lost when the stream dies, instead of staying on running', async () => {
  MockEventStream.instances = []
  // The first stream drops mid-job; the reconnect is refused, as a restarted server does with a 404.
  mockApi({
    'GET /api/jobs/j1/events': (init: RequestInit, url: string) =>
      MockEventStream.instances.length ? new Response(JSON.stringify({ error: 'unknown job' }), { status: 404 }) : new MockEventStream(url, init),
  })
  renderWithProviders(<JobPanel jobId="j1" />)
  const source = MockEventStream.instances[0]
  await act(() => source.emit({ seq: 1, time: '2026-09-29T10:00:00+00:00', message: 'Investigating x' }))
  expect(screen.getByText('running')).toBeInTheDocument()
  await act(() => source.fail())
  expect(screen.getByText('unknown')).toBeInTheDocument()
  expect(screen.queryByText('running')).not.toBeInTheDocument()
  expect(screen.getByText(/Lost the connection to this job/)).toBeInTheDocument()
  expect(screen.queryByText('This job is no longer available.')).not.toBeInTheDocument()
})

test('settings follows an ATT&CK update found in the job list, so its progress survives a navigation', async () => {
  MockEventStream.instances = []
  mockApi({
    'GET /api/settings': { attack: { present: true, techniques: 10, groups: 2, software: 3 }, claude: { found: true }, config: {}, home: 'C:/argus', llm: LLM },
    'GET /api/jobs': [
      { id: 'j2', kind: 'investigate', params: { target: 'x' }, state: 'running', created_at: '', started_at: null, finished_at: null, message: null, result: null, events: 0 },
      { id: 'j1', kind: 'attack_update', params: {}, state: 'running', created_at: '', started_at: null, finished_at: null, message: null, result: null, events: 1 },
    ],
  })
  renderWithProviders(<SettingsPage />)
  expect(await screen.findByText('ATT&CK update')).toBeInTheDocument()
  expect(MockEventStream.instances.map((source) => source.url)).toEqual(['/api/jobs/j1/events'])
})


test('the ATT&CK update warns before it runs, and Cancel fires nothing', async () => {
  MockEventStream.instances = []
  const calls: unknown[] = []
  mockApi({
    'GET /api/settings': { attack: { present: true, techniques: 10, groups: 2, software: 3 }, claude: { found: true }, config: {}, home: 'C:/argus', llm: LLM },
    'POST /api/jobs': (init: RequestInit) => { calls.push(JSON.parse(String(init.body))); return { id: 'j9', kind: 'attack_update', params: {}, state: 'queued', created_at: '', started_at: null, finished_at: null, message: null, result: null, events: 0 } },
  })
  renderWithProviders(<SettingsPage />)

  // Opening the dialog does NOT start the job, and it says what the action costs: an outbound
  // download from MITRE, and that no indicators leave the machine.
  await userEvent.click(await screen.findByRole('button', { name: 'Update ATT&CK' }))
  const dialog = screen.getByRole('dialog')
  expect(dialog).toHaveTextContent(/outbound network request/i)
  expect(dialog).toHaveTextContent(/no indicators of yours leave the machine/i)
  expect(calls).toEqual([])

  // Cancel closes it and still fires nothing.
  await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(calls).toEqual([])

  // Only confirming starts the job.
  await userEvent.click(screen.getByRole('button', { name: 'Update ATT&CK' }))
  await userEvent.click(screen.getByRole('button', { name: 'Download & update' }))
  expect(calls).toEqual([{ kind: 'attack_update' }])
})
