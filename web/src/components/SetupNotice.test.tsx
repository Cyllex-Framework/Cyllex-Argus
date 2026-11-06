import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SetupNotice } from './SetupNotice'
import { MockEventStream, mockApi, renderWithProviders } from '../test/utils'

const settings = (present: boolean, found: boolean) => ({
  attack: { present, techniques: present ? 10 : 0, groups: present ? 2 : 0, software: present ? 3 : 0 },
  claude: { found }, config: {}, home: 'C:/argus',
})
const job = (id: string, state = 'queued', message: string | null = null) => ({
  id, kind: 'attack_update', params: {}, state, created_at: '', started_at: null, finished_at: null, message, result: null, events: 0,
})
const renderNotice = () =>
  renderWithProviders(<SetupNotice id="setup" needs={['attack', 'claude']} purpose="start an investigation" />)

beforeEach(() => {
  MockEventStream.instances = []
})

test('shows nothing when every prerequisite is in place', async () => {
  const fetchMock = mockApi({ 'GET /api/settings': settings(true, true), 'GET /api/jobs': [] })
  const { container } = renderNotice()
  await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url) === '/api/settings')).toBe(true))
  await waitFor(() => expect(container).toBeEmptyDOMElement())
})

test('only the prerequisites the page needs are listed', async () => {
  mockApi({ 'GET /api/settings': settings(true, false), 'GET /api/jobs': [] })
  const { container } = renderWithProviders(<SetupNotice id="setup" needs={['attack']} purpose="do something" />)
  await waitFor(() => expect(container).toBeEmptyDOMElement())
  expect(screen.queryByText(/Claude Code CLI not found/)).not.toBeInTheDocument()
})

test('missing ATT&CK data: explains why and starts the update right there, then disappears when it is loaded', async () => {
  let present = false
  const fetchMock = mockApi({
    'GET /api/settings': () => settings(present, true),
    'GET /api/jobs': [],
    'POST /api/jobs': job('a1'),
  })
  renderNotice()
  const notice = await screen.findByRole('region', { name: 'Finish setup' })
  expect(notice).toHaveAttribute('id', 'setup')
  expect(notice).toHaveTextContent('Argus needs this before it can start an investigation.')
  expect(notice).toHaveTextContent('MITRE ATT&CK data is missing')
  expect(notice).toHaveTextContent(/maps the techniques .* to MITRE ATT&CK/)
  await userEvent.click(screen.getByRole('button', { name: 'Update ATT&CK' }))
  const call = fetchMock.mock.calls.find(([url, init]) => String(url) === '/api/jobs' && init?.method === 'POST')!
  expect(JSON.parse(String(call[1]!.body))).toEqual({ kind: 'attack_update' })
  expect(await screen.findByText('ATT&CK update')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /ATT&CK/ })).not.toBeInTheDocument() // no second update while one runs
  const source = MockEventStream.instances[0]
  expect(source.url).toBe('/api/jobs/a1/events')
  await act(() => source.emit({ seq: 1, time: '2026-09-29T10:00:00+00:00', message: 'Downloading MITRE ATT&CK Enterprise' }))
  expect(screen.getByText('Downloading MITRE ATT&CK Enterprise')).toBeInTheDocument()
  present = true
  await act(() => source.emitEnd({ ...job('a1', 'finished', 'ATT&CK loaded: 2 techniques'), events: 1 }))
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Finish setup' })).not.toBeInTheDocument())
})

test('an update already running elsewhere is followed instead of offering a second one', async () => {
  mockApi({ 'GET /api/settings': settings(false, true), 'GET /api/jobs': [job('a7', 'running')] })
  renderNotice()
  expect(await screen.findByText('ATT&CK update')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /ATT&CK/ })).not.toBeInTheDocument()
  expect(MockEventStream.instances.map((source) => source.url)).toEqual(['/api/jobs/a7/events'])
})

test('a failed update shows its error and offers a retry', async () => {
  let jobs = [job('a1', 'running')]
  const fetchMock = mockApi({
    'GET /api/settings': settings(false, true),
    'GET /api/jobs': () => jobs,
    'POST /api/jobs': job('a2'),
  })
  renderNotice()
  expect(await screen.findByText('ATT&CK update')).toBeInTheDocument()
  jobs = [job('a1', 'failed', 'ConnectError: no route to github.com')]
  await act(() => MockEventStream.instances[0].emitEnd(jobs[0]))
  expect(await screen.findByText('ConnectError: no route to github.com')).toBeInTheDocument()
  await userEvent.click(await screen.findByRole('button', { name: 'Retry ATT&CK update' }))
  await waitFor(() => expect(fetchMock.mock.calls.some(([url, init]) => String(url) === '/api/jobs' && init?.method === 'POST')).toBe(true))
  await waitFor(() => expect(MockEventStream.instances.at(-1)!.url).toBe('/api/jobs/a2/events'))
})

test('a refused update start shows the server message', async () => {
  mockApi({
    'GET /api/settings': settings(false, true), 'GET /api/jobs': [],
    'POST /api/jobs': new Response(JSON.stringify({ error: 'an identical job is already queued or running' }), { status: 409 }),
  })
  renderNotice()
  await userEvent.click(await screen.findByRole('button', { name: 'Update ATT&CK' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('an identical job is already queued or running')
})

test('missing Claude Code CLI: says how to fix it, with no button', async () => {
  mockApi({ 'GET /api/settings': settings(true, false), 'GET /api/jobs': [] })
  renderNotice()
  const notice = await screen.findByRole('region', { name: 'Finish setup' })
  expect(notice).toHaveTextContent('Claude Code CLI not found')
  expect(notice).toHaveTextContent(/Install Claude Code, run claude once to log in/)
  expect(notice).toHaveTextContent(/restart argus serve/)
  expect(screen.queryByRole('button')).not.toBeInTheDocument()
})

test('both missing: lists both, in one notice', async () => {
  mockApi({ 'GET /api/settings': settings(false, false), 'GET /api/jobs': [] })
  renderNotice()
  const notice = await screen.findByRole('region', { name: 'Finish setup' })
  expect(notice).toHaveTextContent('Argus needs these before it can start an investigation.')
  expect(notice).toHaveTextContent('MITRE ATT&CK data is missing')
  expect(notice).toHaveTextContent('Claude Code CLI not found')
})
