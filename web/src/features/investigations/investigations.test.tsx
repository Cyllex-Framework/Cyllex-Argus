import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Link } from 'react-router-dom'
import { InvestigationsPage } from './InvestigationsPage'
import { InvestigationDetailPage } from './InvestigationDetailPage'
import { stageSummary } from './NewInvestigationCard'
import { formatDate, formatDateTime } from '../../lib/format'
import { MockEventStream, mockApi, renderWithProviders } from '../../test/utils'

const SUMMARY = {
  id: 3, target: 'Scattered Spider', state: 'paused', started_at: '2026-09-29T10:00:00+00:00', finished_at: null,
  collected: true, stage_counts: { validated: 2, collected: 1 },
}
const DETAIL = {
  ...SUMMARY,
  documents: [
    { id: 7, title: 'Deep dive', publisher: 'Mandiant', stage: 'validated', published_at: '2025-01-10',
      retrieved_at: '2026-09-29T10:01:00+00:00', failure_reason: null, location: 'https://mandiant.example/r' },
  ],
  failures: [{ title: 'Gone <i>away</i>', reason: 'HTTP 404' }],
}
const job = (id: string, kind: string, params: Record<string, unknown>, state = 'queued') => ({
  id, kind, params, state, created_at: 't', started_at: null, finished_at: null, message: null, result: null, events: 0,
})
const postedBody = (fetchMock: ReturnType<typeof mockApi>) => {
  const call = fetchMock.mock.calls.find(([url, init]) => String(url) === '/api/jobs' && init?.method === 'POST')!
  return JSON.parse(String(call[1]!.body))
}

beforeEach(() => {
  MockEventStream.instances = []
})

test('stageSummary formats counts in pipeline order', () => {
  expect(stageSummary({ failed: 1, validated: 2, collected: 3 })).toBe('collected 3 · validated 2 · failed 1')
  expect(stageSummary({})).toBe('-')
})

test('list shows investigations with links, state and stage counts', async () => {
  mockApi({ 'GET /api/investigations': [SUMMARY], 'GET /api/jobs': [] })
  renderWithProviders(<InvestigationsPage />)
  const link = await screen.findByRole('link', { name: 'Scattered Spider' })
  expect(link).toHaveAttribute('href', '/investigations/3/dashboard')
  const row = link.closest('tr')!
  expect(within(row).getByText('paused')).toBeInTheDocument()
  expect(within(row).getByText('collected 1 · validated 2')).toBeInTheDocument()
})

test('list empty state', async () => {
  mockApi({ 'GET /api/investigations': [], 'GET /api/jobs': [] })
  renderWithProviders(<InvestigationsPage />)
  expect(await screen.findByText(/No investigations yet/)).toBeInTheDocument()
})

test('starting an investigation posts the target and max docs and follows the job', async () => {
  const fetchMock = mockApi({
    'GET /api/investigations': [], 'GET /api/jobs': [],
    'POST /api/jobs': job('j1', 'investigate', { target: 'Octo Tempest', max_docs: 5 }),
  })
  renderWithProviders(<InvestigationsPage />)
  const start = screen.getByRole('button', { name: 'Start investigation' })
  expect(start).toBeDisabled()
  await userEvent.type(screen.getByLabelText('Threat to investigate'), '  Octo Tempest ')
  await userEvent.type(screen.getByLabelText('Maximum documents (optional)'), '5')
  await userEvent.click(start)
  expect(await screen.findByText('Investigation progress')).toBeInTheDocument()
  expect(postedBody(fetchMock)).toEqual({ kind: 'investigate', target: 'Octo Tempest', max_docs: 5 })
  expect(MockEventStream.instances[0].url).toBe('/api/jobs/j1/events')
})

test('parallel workers selector sends `concurrency` and is omitted when left at 1', async () => {
  const fetchMock = mockApi({
    'GET /api/investigations': [], 'GET /api/jobs': [],
    'POST /api/jobs': job('j-c', 'investigate', { target: 'APT29', concurrency: 4 }),
  })
  renderWithProviders(<InvestigationsPage />)
  await userEvent.type(screen.getByLabelText('Threat to investigate'), 'APT29')
  const workers = screen.getByLabelText('Parallel workers')
  // Default renders as 1 — not sent on the wire so the server's own default kicks in and old
  // Argus servers that predate the field keep working.
  expect(workers).toHaveValue(1)
  fireEvent.change(workers, { target: { value: '4' } })
  await userEvent.click(screen.getByRole('button', { name: 'Start investigation' }))
  await screen.findByText('Investigation progress')
  expect(postedBody(fetchMock)).toEqual({ kind: 'investigate', target: 'APT29', concurrency: 4 })
})


test('max docs is omitted when empty', async () => {
  const fetchMock = mockApi({ 'GET /api/investigations': [], 'GET /api/jobs': [], 'POST /api/jobs': job('j2', 'investigate', { target: 'APT29' }) })
  renderWithProviders(<InvestigationsPage />)
  await userEvent.type(screen.getByLabelText('Threat to investigate'), 'APT29')
  await userEvent.click(screen.getByRole('button', { name: 'Start investigation' }))
  await screen.findByText('Investigation progress')
  expect(postedBody(fetchMock)).toEqual({ kind: 'investigate', target: 'APT29' })
})

test('start shows the server refusal (ATT&CK missing, Claude missing)', async () => {
  mockApi({
    'GET /api/investigations': [], 'GET /api/jobs': [],
    'POST /api/jobs': new Response(JSON.stringify({ error: 'Claude Code CLI not found; install it and log in' }), { status: 503 }),
  })
  renderWithProviders(<InvestigationsPage />)
  await userEvent.type(screen.getByLabelText('Threat to investigate'), 'APT29')
  await userEvent.click(screen.getByRole('button', { name: 'Start investigation' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Claude Code CLI not found')
})

test('detail shows documents and failures, and Resume posts the investigation id', async () => {
  const fetchMock = mockApi({
    'GET /api/investigations/3': DETAIL, 'GET /api/jobs': [],
    'POST /api/jobs': job('j3', 'resume', { investigation_id: 3 }),
  })
  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  expect(await screen.findByRole('heading', { name: /Scattered Spider/ })).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Deep dive' })).toHaveAttribute('href', '/documents/7')
  expect(screen.getByText('Gone <i>away</i>')).toBeInTheDocument()
  expect(screen.getByText('HTTP 404')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Resume' }))
  expect(await screen.findByText('Resume progress')).toBeInTheDocument()
  expect(postedBody(fetchMock)).toEqual({ kind: 'resume', investigation_id: 3 })
})

test('detail links to the analysis dashboard', async () => {
  mockApi({ 'GET /api/investigations/3': DETAIL, 'GET /api/jobs': [] })
  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  expect(await screen.findByRole('link', { name: 'View analysis dashboard' })).toHaveAttribute('href', '/investigations/3/dashboard')
})

test('finished investigations have no Resume button', async () => {
  mockApi({ 'GET /api/investigations/3': { ...DETAIL, state: 'finished', finished_at: '2026-09-29T11:00:00+00:00' }, 'GET /api/jobs': [] })
  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  await screen.findByRole('heading', { name: /Scattered Spider/ })
  expect(screen.queryByRole('button', { name: 'Resume' })).not.toBeInTheDocument()
})

test('Resume is disabled while a resume job for this investigation is active', async () => {
  mockApi({ 'GET /api/investigations/3': DETAIL, 'GET /api/jobs': [job('j4', 'resume', { investigation_id: 3 }, 'running')] })
  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  await screen.findByRole('heading', { name: /Scattered Spider/ })
  await waitFor(() => expect(screen.getByRole('button', { name: 'Resume' })).toBeDisabled())
})

test.each([
  ['a queued resume', job('j4', 'resume', { investigation_id: 3 }, 'queued')],
  ['a running investigate job for its target', job('j5', 'investigate', { target: ' scattered spider ' }, 'running')],
  ['a queued investigate job for its target', job('j5', 'investigate', { target: 'Scattered Spider', max_docs: 5 }, 'queued')],
])('Resume is disabled while %s is active', async (_case, active) => {
  mockApi({ 'GET /api/investigations/3': DETAIL, 'GET /api/jobs': [active] })
  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  await screen.findByRole('heading', { name: /Scattered Spider/ })
  await waitFor(() => expect(screen.getByRole('button', { name: 'Resume' })).toBeDisabled())
})

test('Resume stays enabled for jobs that are finished or belong to another investigation', async () => {
  const fetchMock = mockApi({
    'GET /api/investigations/3': DETAIL,
    'GET /api/jobs': [
      job('j5', 'resume', { investigation_id: 4 }, 'running'),
      job('j6', 'resume', { investigation_id: 3 }, 'finished'),
      job('j7', 'investigate', { target: 'APT29' }, 'running'),
      { ...job('j8', 'investigate', { target: 'Scattered Spider' }, 'finished'), result: { investigation_id: 3 } },
    ],
  })
  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  await screen.findByRole('heading', { name: /Scattered Spider/ })
  await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url) === '/api/jobs')).toBe(true))
  await act(async () => {}) // let the jobs response settle before asserting that the button is still enabled
  expect(screen.getByRole('button', { name: 'Resume' })).toBeEnabled()
})

test('a refused start shows the server text and does not open a progress panel', async () => {
  mockApi({
    'GET /api/investigations': [], 'GET /api/investigations/3': DETAIL, 'GET /api/jobs': [],
    'POST /api/jobs': new Response(JSON.stringify({ error: 'an identical resume job is already queued or running' }), { status: 409 }),
  })
  const list = renderWithProviders(<InvestigationsPage />)
  await userEvent.type(screen.getByLabelText('Threat to investigate'), 'APT29')
  await userEvent.click(screen.getByRole('button', { name: 'Start investigation' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('an identical resume job is already queued or running')
  expect(screen.queryByText('Investigation progress')).not.toBeInTheDocument()
  list.unmount()

  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  await userEvent.click(await screen.findByRole('button', { name: 'Resume' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('an identical resume job is already queued or running')
  expect(screen.queryByText('Resume progress')).not.toBeInTheDocument()
})

test('max docs is read as a whole number, so exponent notation is not truncated', async () => {
  const fetchMock = mockApi({ 'GET /api/investigations': [], 'GET /api/jobs': [], 'POST /api/jobs': job('j8', 'investigate', { target: 'APT29', max_docs: 10 }) })
  renderWithProviders(<InvestigationsPage />)
  await userEvent.type(screen.getByLabelText('Threat to investigate'), 'APT29')
  fireEvent.change(screen.getByLabelText('Maximum documents (optional)'), { target: { value: '1e1' } })
  await userEvent.click(screen.getByRole('button', { name: 'Start investigation' }))
  await screen.findByText('Investigation progress')
  expect(postedBody(fetchMock)).toEqual({ kind: 'investigate', target: 'APT29', max_docs: 10 })
})

test('list formats its dates through the shared helper', async () => {
  const finished = { ...SUMMARY, id: 4, target: 'APT29', state: 'finished', finished_at: '2026-09-29T11:00:00+00:00' }
  mockApi({ 'GET /api/investigations': [SUMMARY, finished], 'GET /api/jobs': [] })
  renderWithProviders(<InvestigationsPage />)
  const running = (await screen.findByRole('link', { name: 'Scattered Spider' })).closest('tr')!
  expect(within(running).getByText(formatDateTime(SUMMARY.started_at))).toBeInTheDocument()
  expect(within(running).getByText('-', { selector: 'td:nth-last-child(2)' })).toBeInTheDocument() // not finished yet
  const done = screen.getByRole('link', { name: 'APT29' }).closest('tr')!
  expect(within(done).getByText(formatDateTime(finished.finished_at))).toBeInTheDocument()
})

test('detail formats its dates and shows the stage counts and the empty states', async () => {
  const finished = { ...DETAIL, state: 'finished', finished_at: '2026-09-29T11:00:00+00:00' }
  mockApi({
    'GET /api/investigations/3': { ...finished, stage_counts: { validated: 2, failed: 1 } },
    'GET /api/investigations/4': { ...SUMMARY, id: 4, target: 'Quiet', documents: [], failures: [], stage_counts: {} },
    'GET /api/jobs': [],
  })
  const first = renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  await screen.findByRole('heading', { name: /Scattered Spider/ })
  expect(screen.getByText(`Started ${formatDateTime(finished.started_at)}`)).toBeInTheDocument()
  expect(screen.getByText(`Finished ${formatDateTime(finished.finished_at)}`)).toBeInTheDocument()
  const row = screen.getByRole('link', { name: 'Deep dive' }).closest('tr')!
  expect(within(row).getByText(formatDate('2025-01-10'))).toBeInTheDocument()
  expect(screen.getByText('validated', { selector: '.stat-label' }).closest('.stat-card')).toHaveTextContent('2')
  expect(screen.getByText('failed', { selector: '.stat-label' }).closest('.stat-card')).toHaveTextContent('1')
  expect(screen.getByText('collected', { selector: '.stat-label' }).closest('.stat-card')).toHaveTextContent('0')
  first.unmount()

  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/4', path: '/investigations/:id' })
  expect(await screen.findByText('No documents recorded for this investigation.')).toBeInTheDocument()
  expect(screen.queryByText('Failures')).not.toBeInTheDocument()
})

test('detail shows the server error for an unknown investigation', async () => {
  mockApi({
    'GET /api/investigations/99': new Response(JSON.stringify({ error: 'unknown investigation' }), { status: 404 }),
    'GET /api/jobs': [],
  })
  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/99', path: '/investigations/:id' })
  expect(await screen.findByRole('alert')).toHaveTextContent('unknown investigation')
})

test('detail refreshes when the resume job ends', async () => {
  let loads = 0
  mockApi({
    'GET /api/investigations/3': () => (loads++ === 0 ? DETAIL : { ...DETAIL, state: 'finished', finished_at: '2026-09-29T11:00:00+00:00' }),
    'GET /api/jobs': [],
    'POST /api/jobs': job('j3', 'resume', { investigation_id: 3 }),
  })
  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  await userEvent.click(await screen.findByRole('button', { name: 'Resume' }))
  await screen.findByText('Resume progress')
  await act(() => MockEventStream.instances[0].emitEnd(job('j3', 'resume', { investigation_id: 3 }, 'finished')))
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Resume' })).not.toBeInTheDocument())
  expect(screen.getByText(/Finished /)).toBeInTheDocument()
})

test('moving to another investigation drops the resume progress of the previous one', async () => {
  mockApi({
    'GET /api/investigations/3': DETAIL,
    'GET /api/investigations/4': { ...DETAIL, id: 4, target: 'APT29' },
    'GET /api/jobs': [],
    'POST /api/jobs': job('j3', 'resume', { investigation_id: 3 }),
  })
  renderWithProviders(
    <>
      <Link to="/investigations/4">go to second</Link>
      <InvestigationDetailPage />
    </>,
    { route: '/investigations/3', path: '/investigations/:id' },
  )
  await userEvent.click(await screen.findByRole('button', { name: 'Resume' }))
  expect(await screen.findByText('Resume progress')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('link', { name: 'go to second' }))
  expect(await screen.findByRole('heading', { name: /APT29/ })).toBeInTheDocument()
  expect(screen.queryByText('Resume progress')).not.toBeInTheDocument()
})

test('the progress panel comes from the server job list, so a running investigation is still followed after a navigation', async () => {
  mockApi({
    'GET /api/investigations': [],
    'GET /api/jobs': [job('j2', 'ingest', {}, 'running'), job('j1', 'investigate', { target: 'Octo Tempest' }, 'running')],
  })
  renderWithProviders(<InvestigationsPage />)
  expect(await screen.findByText('Investigation progress')).toBeInTheDocument()
  expect(MockEventStream.instances.map((source) => source.url)).toEqual(['/api/jobs/j1/events'])
})

test('with no investigation running, the most recent one stays on screen with its result', async () => {
  mockApi({
    'GET /api/investigations': [],
    'GET /api/jobs': [job('j5', 'resume', { investigation_id: 3 }, 'finished'), job('j4', 'investigate', { target: 'APT29' }, 'finished')],
  })
  renderWithProviders(<InvestigationsPage />)
  expect(await screen.findByText('Investigation progress')).toBeInTheDocument()
  expect(MockEventStream.instances.map((source) => source.url)).toEqual(['/api/jobs/j4/events'])
})

test('no investigation job at all means no progress panel', async () => {
  mockApi({ 'GET /api/investigations': [], 'GET /api/jobs': [job('j2', 'ingest', {}, 'finished')] })
  const { queryClient } = renderWithProviders(<InvestigationsPage />)
  await waitFor(() => expect(queryClient.getQueryData(['jobs'])).toBeDefined())
  expect(screen.queryByText('Investigation progress')).not.toBeInTheDocument()
  expect(MockEventStream.instances).toHaveLength(0)
})

test('detail follows a running resume of this investigation found in the job list', async () => {
  mockApi({
    'GET /api/investigations/3': DETAIL,
    'GET /api/jobs': [job('j9', 'resume', { investigation_id: 4 }, 'running'), job('j8', 'resume', { investigation_id: 3 }, 'queued')],
  })
  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  expect(await screen.findByText('Resume progress')).toBeInTheDocument()
  expect(MockEventStream.instances.map((source) => source.url)).toEqual(['/api/jobs/j8/events'])
})

test('detail shows the last job that produced this investigation', async () => {
  const done = { ...job('j7', 'investigate', { target: 'Scattered Spider' }, 'finished'), result: { investigation_id: 3 } }
  const other = { ...job('j6', 'investigate', { target: 'APT29' }, 'finished'), result: { investigation_id: 4 } }
  mockApi({ 'GET /api/investigations/3': DETAIL, 'GET /api/jobs': [other, done] })
  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  expect(await screen.findByText('Investigation progress')).toBeInTheDocument()
  expect(MockEventStream.instances.map((source) => source.url)).toEqual(['/api/jobs/j7/events'])
})

const settings = (present: boolean, found: boolean) => ({
  attack: { present, techniques: 0, groups: 0, software: 0 }, claude: { found }, config: {}, home: 'C:/argus',
})

test('Start investigation is disabled, pointing at the setup notice, until the ATT&CK update it starts has loaded the data', async () => {
  let present = false
  mockApi({
    'GET /api/settings': () => settings(present, true),
    'GET /api/investigations': [], 'GET /api/jobs': [],
    'POST /api/jobs': job('a1', 'attack_update', {}),
  })
  renderWithProviders(<InvestigationsPage />)
  const notice = await screen.findByRole('region', { name: 'Finish setup' })
  await userEvent.type(screen.getByLabelText('Threat to investigate'), 'APT29')
  const start = screen.getByRole('button', { name: 'Start investigation' })
  expect(start).toBeDisabled()
  expect(start).toHaveAttribute('aria-describedby', notice.id)
  await userEvent.click(within(notice).getByRole('button', { name: 'Update ATT&CK' }))
  await waitFor(() => expect(MockEventStream.instances.some((stream) => stream.url === '/api/jobs/a1/events')).toBe(true))
  const source = MockEventStream.instances.find((stream) => stream.url === '/api/jobs/a1/events')!
  present = true
  await act(() => source.emitEnd({ ...job('a1', 'attack_update', {}, 'finished'), message: 'ATT&CK loaded' }))
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Finish setup' })).not.toBeInTheDocument())
  expect(screen.getByRole('button', { name: 'Start investigation' })).toBeEnabled()
  expect(screen.getByRole('button', { name: 'Start investigation' })).not.toHaveAttribute('aria-describedby')
})

test('Start investigation is disabled while the Claude Code CLI is missing, and the notice says how to fix it', async () => {
  mockApi({ 'GET /api/settings': settings(true, false), 'GET /api/investigations': [], 'GET /api/jobs': [] })
  renderWithProviders(<InvestigationsPage />)
  expect(await screen.findByRole('region', { name: 'Finish setup' })).toHaveTextContent('restart argus serve')
  await userEvent.type(screen.getByLabelText('Threat to investigate'), 'APT29')
  expect(screen.getByRole('button', { name: 'Start investigation' })).toBeDisabled()
})

test('a 409 for missing ATT&CK data refreshes the settings, so the notice and its button appear instead of a dead end', async () => {
  let present = true
  const fetchMock = mockApi({
    'GET /api/settings': () => settings(present, true),
    'GET /api/investigations': [], 'GET /api/jobs': [],
    'POST /api/jobs': (init: RequestInit) => {
      if (JSON.parse(String(init.body)).kind === 'attack_update') return job('a1', 'attack_update', {})
      present = false // the data was deleted after the page loaded
      return new Response(JSON.stringify({ error: 'ATT&CK data is missing; run the ATT&CK update first (Settings → Update ATT&CK)' }), { status: 409 })
    },
  })
  renderWithProviders(<InvestigationsPage />)
  await waitFor(() => expect(fetchMock.mock.calls.filter(([url]) => String(url) === '/api/settings')).toHaveLength(1))
  await userEvent.type(screen.getByLabelText('Threat to investigate'), 'APT29')
  await userEvent.click(screen.getByRole('button', { name: 'Start investigation' }))
  const notice = await screen.findByRole('region', { name: 'Finish setup' })
  expect(screen.getByRole('button', { name: 'Start investigation' })).toBeDisabled()
  // Fixed from the notice, the page is ready again, without the refusal that the fix has made stale.
  await userEvent.click(within(notice).getByRole('button', { name: 'Update ATT&CK' }))
  await waitFor(() => expect(MockEventStream.instances.some((stream) => stream.url === '/api/jobs/a1/events')).toBe(true))
  present = true
  await act(() => MockEventStream.instances.find((stream) => stream.url === '/api/jobs/a1/events')!
    .emitEnd({ ...job('a1', 'attack_update', {}, 'finished'), message: 'ATT&CK loaded' }))
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Finish setup' })).not.toBeInTheDocument())
  expect(screen.getByRole('button', { name: 'Start investigation' })).toBeEnabled()
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})

test('Resume is disabled, pointing at the setup notice, while a prerequisite is missing', async () => {
  mockApi({ 'GET /api/settings': settings(false, true), 'GET /api/investigations/3': DETAIL, 'GET /api/jobs': [] })
  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  const notice = await screen.findByRole('region', { name: 'Finish setup' })
  expect(notice).toHaveTextContent('resume this investigation')
  const resume = screen.getByRole('button', { name: 'Resume' })
  expect(resume).toBeDisabled()
  expect(resume).toHaveAttribute('aria-describedby', notice.id)
})

test('a finished investigation shows no setup notice: there is nothing to resume', async () => {
  const fetchMock = mockApi({ 'GET /api/settings': settings(false, false), 'GET /api/investigations/3': { ...DETAIL, state: 'finished' }, 'GET /api/jobs': [] })
  renderWithProviders(<InvestigationDetailPage />, { route: '/investigations/3', path: '/investigations/:id' })
  await screen.findByRole('heading', { name: /Scattered Spider/ })
  await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url) === '/api/settings')).toBe(true))
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)))
  expect(screen.queryByRole('region', { name: 'Finish setup' })).not.toBeInTheDocument()
})

test('the list shows who started each investigation', async () => {
  mockApi({ 'GET /api/investigations': [{ ...SUMMARY, started_by: 'alice' }], 'GET /api/jobs': [] })
  renderWithProviders(<InvestigationsPage />)
  const link = await screen.findByRole('link', { name: 'Scattered Spider' })
  expect(within(link.closest('tr')!).getByText('alice')).toBeInTheDocument()
})
