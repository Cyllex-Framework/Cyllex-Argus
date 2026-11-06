import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Link } from 'react-router-dom'
import { DocumentsPage } from './DocumentsPage'
import { DocumentViewerPage } from './DocumentViewerPage'
import { formatDate, formatDateTime } from '../../lib/format'
import { MockEventStream, mockApi, renderWithProviders } from '../../test/utils'

const TEXT = 'Intro. The actor called the IT help desk. <script>alert(1)</script> Retail victims were hit.'
const at = (quote: string): [number, number] => [TEXT.indexOf(quote), TEXT.indexOf(quote) + quote.length]
const SUMMARY = {
  id: 7, title: 'Deep dive <b>bold</b>', publisher: 'Mandiant', stage: 'validated', published_at: '2025-01-10',
  retrieved_at: '2025-01-11T10:00:00+00:00', failure_reason: null, location: 'https://mandiant.example/r',
}
const DETAIL = {
  ...SUMMARY,
  text: TEXT,
  claims: [
    { id: 1, subject: 'Scattered Spider', predicate: 'uses', object: 'Spearphishing Voice', quote: 'called the IT help desk',
      quote_status: 'verified', polarity: 'asserts', span: at('called the IT help desk') },
    { id: 2, subject: 'Scattered Spider', predicate: 'targets', object: 'retail', quote: 'Retail victims',
      quote_status: 'verified_fuzzy', polarity: 'asserts', span: at('Retail victims') },
    { id: 3, subject: 'Scattered Spider', predicate: 'uses', object: 'Mimikatz', quote: 'ran mimikatz',
      quote_status: 'rejected', polarity: 'asserts', span: null },
  ],
}
const JOB = { id: 'j9', kind: 'ingest', params: { files: ['a.txt'], target: 'Scattered Spider' }, state: 'queued',
  created_at: 't', started_at: null, finished_at: null, message: null, result: null, events: 0 }

beforeEach(() => {
  MockEventStream.instances = []
})

test('documents list shows rows and filters by stage', async () => {
  const fetchMock = mockApi({ 'GET /api/documents': [SUMMARY, { ...SUMMARY, id: 8, title: 'Broken', stage: 'failed', failure_reason: 'HTTP 403' }] })
  renderWithProviders(<DocumentsPage />)
  expect(await screen.findByRole('link', { name: 'Deep dive <b>bold</b>' })).toHaveAttribute('href', '/documents/7')
  expect(screen.getByText('HTTP 403')).toBeInTheDocument()
  await userEvent.selectOptions(screen.getByLabelText('Filter by stage'), 'failed')
  await screen.findByRole('link', { name: 'Broken' })
  expect(fetchMock.mock.calls.some(([url]) => String(url).includes('stage=failed'))).toBe(true)
})

test('documents empty state', async () => {
  mockApi({ 'GET /api/documents': [] })
  renderWithProviders(<DocumentsPage />)
  expect(await screen.findByText(/No documents yet/)).toBeInTheDocument()
})

test('ingest uploads the selected files with the focus threat and follows the job', async () => {
  const fetchMock = mockApi({ 'GET /api/documents': [], 'POST /api/ingest': JOB })
  renderWithProviders(<DocumentsPage />)
  const button = screen.getByRole('button', { name: /Ingest/ })
  expect(button).toBeDisabled()
  const file = new File(['report body'], 'report.txt', { type: 'text/plain' })
  await userEvent.upload(screen.getByLabelText(/files to ingest/i), file)
  await userEvent.type(screen.getByLabelText('Focus threat (optional)'), 'Scattered Spider')
  await userEvent.click(screen.getByRole('button', { name: 'Ingest 1 file(s)' }))
  expect(await screen.findByText('Ingest progress')).toBeInTheDocument()
  const call = fetchMock.mock.calls.find(([url]) => String(url) === '/api/ingest')
  expect(call).toBeDefined()
  const init = call![1] as RequestInit
  expect(new Headers(init.headers).get('X-Argus-CSRF')).toBe('1')
  const form = init.body as FormData
  expect((form.getAll('files')[0] as File).name).toBe('report.txt')
  expect(form.get('target')).toBe('Scattered Spider')
  expect(MockEventStream.instances[0].url).toBe('/api/jobs/j9/events')
})

test('ingest shows the server error', async () => {
  mockApi({
    'GET /api/documents': [],
    'POST /api/ingest': new Response(JSON.stringify({ error: 'ATT&CK data is missing; run the ATT&CK update first' }), { status: 409 }),
  })
  renderWithProviders(<DocumentsPage />)
  await userEvent.upload(screen.getByLabelText(/files to ingest/i), new File(['x'], 'a.txt', { type: 'text/plain' }))
  await userEvent.click(screen.getByRole('button', { name: 'Ingest 1 file(s)' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('ATT&CK data is missing')
})

test('ingest refuses more than 20 files client-side', async () => {
  mockApi({ 'GET /api/documents': [] })
  renderWithProviders(<DocumentsPage />)
  const files = Array.from({ length: 21 }, (_, i) => new File(['x'], `f${i}.txt`, { type: 'text/plain' }))
  await userEvent.upload(screen.getByLabelText(/files to ingest/i), files)
  expect(screen.getByText('At most 20 files per upload.')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Ingest 21 file(s)' })).toBeDisabled()
})

test('viewer highlights located quotes, keeps hostile text as text and selects claims', async () => {
  mockApi({ 'GET /api/documents/7': DETAIL })
  renderWithProviders(<DocumentViewerPage />, { route: '/documents/7', path: '/documents/:id' })
  expect(await screen.findByRole('heading', { name: 'Deep dive <b>bold</b>' })).toBeInTheDocument()
  const body = screen.getByTestId('document-text')
  expect(body.textContent).toBe(TEXT)
  expect(body.querySelector('script')).toBeNull()
  expect(body.querySelector('b')).toBeNull()
  const marks = body.querySelectorAll('mark')
  expect(marks).toHaveLength(2)
  expect(marks[0].textContent).toBe('called the IT help desk')

  const claims = screen.getByRole('region', { name: 'Claims' })
  await userEvent.click(within(claims).getByRole('button', { name: /targets retail/ }))
  expect(marks[1]).toHaveAttribute('data-active', 'true')
  expect(marks[0]).toHaveAttribute('data-active', 'false')
  expect(within(claims).getByRole('button', { name: /targets retail/ })).toHaveAttribute('aria-pressed', 'true')
  expect(within(claims).getByText('Quote not located in the text')).toBeInTheDocument()

  await userEvent.click(marks[0])
  expect(within(claims).getByRole('button', { name: /uses Spearphishing Voice/ })).toHaveAttribute('aria-pressed', 'true')
})

test('viewer shows the failure reason for failed documents', async () => {
  mockApi({ 'GET /api/documents/8': { ...DETAIL, id: 8, stage: 'failed', failure_reason: 'HTTP 403', text: '', claims: [] } })
  renderWithProviders(<DocumentViewerPage />, { route: '/documents/8', path: '/documents/:id' })
  expect(await screen.findByRole('alert')).toHaveTextContent('HTTP 403')
  expect(screen.getByText('No extracted text for this document.')).toBeInTheDocument()
})

test('list formats its dates through the shared helpers and passes the trimmed search to the API', async () => {
  const fetchMock = mockApi({ 'GET /api/documents': [SUMMARY, { ...SUMMARY, id: 9, title: 'Undated report', published_at: null }] })
  renderWithProviders(<DocumentsPage />)
  const row = (await screen.findByRole('link', { name: 'Deep dive <b>bold</b>' })).closest('tr')!
  expect(within(row).getByText(formatDate('2025-01-10'))).toBeInTheDocument()
  expect(within(row).getByText(formatDateTime('2025-01-11T10:00:00+00:00'))).toBeInTheDocument()
  const undated = screen.getByRole('link', { name: 'Undated report' }).closest('tr')!
  expect(within(undated).getByText('-')).toBeInTheDocument()
  await userEvent.type(screen.getByLabelText('Search documents'), ' mandiant ')
  await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('?q=mandiant'))).toBe(true))
})

test('list keeps the previous rows on screen, dimmed, while the next filter loads', async () => {
  let release!: (response: Response) => void
  const next = new Promise<Response>((resolve) => { release = resolve })
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    if (String(input).includes('stage=failed')) return next
    if (!String(input).startsWith('/api/documents')) return Promise.resolve(new Response('{}', { status: 404 }))
    return Promise.resolve(new Response(JSON.stringify([SUMMARY]), { status: 200 }))
  })
  vi.stubGlobal('fetch', fetchMock)
  renderWithProviders(<DocumentsPage />)
  const first = await screen.findByRole('link', { name: 'Deep dive <b>bold</b>' })
  const results = first.closest('[aria-busy]')!
  expect(results).toHaveAttribute('aria-busy', 'false')
  expect(results).not.toHaveClass('opacity-60')

  await userEvent.selectOptions(screen.getByLabelText('Filter by stage'), 'failed')
  await waitFor(() => expect(results).toHaveAttribute('aria-busy', 'true'))
  expect(results).toHaveClass('opacity-60')
  expect(screen.getByRole('link', { name: 'Deep dive <b>bold</b>' })).toBeInTheDocument()
  expect(screen.queryByText('Loading...')).not.toBeInTheDocument()

  release(new Response(JSON.stringify([{ ...SUMMARY, id: 8, title: 'Broken', stage: 'failed' }]), { status: 200 }))
  expect(await screen.findByRole('link', { name: 'Broken' })).toBeInTheDocument()
  expect(screen.queryByRole('link', { name: 'Deep dive <b>bold</b>' })).not.toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Broken' }).closest('[aria-busy]')).toHaveAttribute('aria-busy', 'false')
})

test('a started upload clears the chosen files so the form is ready for the next batch', async () => {
  mockApi({ 'GET /api/documents': [], 'POST /api/ingest': JOB })
  renderWithProviders(<DocumentsPage />)
  const input = screen.getByLabelText(/files to ingest/i) as HTMLInputElement
  await userEvent.upload(input, new File(['x'], 'a.txt', { type: 'text/plain' }))
  await userEvent.click(screen.getByRole('button', { name: 'Ingest 1 file(s)' }))
  expect(await screen.findByText('Ingest progress')).toBeInTheDocument()
  expect(input.files).toHaveLength(0)
  expect(screen.getByRole('button', { name: 'Ingest' })).toBeDisabled()
})

test('viewer aligns highlights when astral characters precede a quote (the API counts code points)', async () => {
  const emoji = String.fromCodePoint(0x1f600)
  const text = `${emoji}${emoji} The actor called the help desk.`
  const quote = 'called the help desk'
  const start = [...text.slice(0, text.indexOf(quote))].length // Python offsets: two emoji count as 2, not 4
  const claim = { ...DETAIL.claims[0], quote, span: [start, start + [...quote].length] }
  mockApi({ 'GET /api/documents/7': { ...DETAIL, text, claims: [claim] } })
  renderWithProviders(<DocumentViewerPage />, { route: '/documents/7', path: '/documents/:id' })
  const body = await screen.findByTestId('document-text')
  expect(body.textContent).toBe(text)
  expect(Array.from(body.querySelectorAll('mark'), (mark) => mark.textContent)).toEqual([quote])
})

test('viewer shows the formatted publication date, or "undated"', async () => {
  mockApi({ 'GET /api/documents/7': DETAIL, 'GET /api/documents/9': { ...DETAIL, id: 9, published_at: null } })
  const first = renderWithProviders(<DocumentViewerPage />, { route: '/documents/7', path: '/documents/:id' })
  await screen.findByRole('heading', { name: 'Deep dive <b>bold</b>' })
  expect(screen.getByText(formatDate('2025-01-10'))).toBeInTheDocument()
  first.unmount()
  renderWithProviders(<DocumentViewerPage />, { route: '/documents/9', path: '/documents/:id' })
  expect(await screen.findByText('undated')).toBeInTheDocument()
})

test('moving to another document resets the selected claim', async () => {
  const OTHER = { ...DETAIL, id: 8, title: 'Second report' }
  mockApi({ 'GET /api/documents/7': DETAIL, 'GET /api/documents/8': OTHER })
  renderWithProviders(
    <>
      <Link to="/documents/8">go to second</Link>
      <DocumentViewerPage />
    </>,
    { route: '/documents/7', path: '/documents/:id' },
  )
  await userEvent.click(await screen.findByRole('button', { name: /targets retail/ }))
  expect(screen.getByRole('button', { name: /targets retail/ })).toHaveAttribute('aria-pressed', 'true')
  await userEvent.click(screen.getByRole('link', { name: 'go to second' }))
  expect(await screen.findByRole('heading', { name: 'Second report' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: /targets retail/ })).toHaveAttribute('aria-pressed', 'false')
  expect(screen.getByTestId('document-text').querySelectorAll('mark[data-active="true"]')).toHaveLength(0)
})

test('the ingest panel comes from the server job list, so a running ingest is still followed after a navigation', async () => {
  mockApi({
    'GET /api/documents': [],
    'GET /api/jobs': [{ ...JOB, id: 'j3', kind: 'attack_update', state: 'running' }, { ...JOB, id: 'j2', state: 'running' }, { ...JOB, id: 'j1', state: 'finished' }],
  })
  renderWithProviders(<DocumentsPage />)
  expect(await screen.findByText('Ingest progress')).toBeInTheDocument()
  expect(MockEventStream.instances.map((source) => source.url)).toEqual(['/api/jobs/j2/events'])
})

const settings = (present: boolean, found: boolean) => ({
  attack: { present, techniques: 0, groups: 0, software: 0 }, claude: { found }, config: {}, home: 'C:/argus',
})

test('ingest is disabled, pointing at the setup notice, while a prerequisite is missing', async () => {
  mockApi({ 'GET /api/settings': settings(true, false), 'GET /api/documents': [], 'GET /api/jobs': [] })
  renderWithProviders(<DocumentsPage />)
  const notice = await screen.findByRole('region', { name: 'Finish setup' })
  expect(notice).toHaveTextContent('ingest documents')
  expect(notice).toHaveTextContent('Claude Code CLI not found')
  await userEvent.upload(screen.getByLabelText(/files to ingest/i), new File(['x'], 'a.txt', { type: 'text/plain' }))
  const button = screen.getByRole('button', { name: 'Ingest 1 file(s)' })
  expect(button).toBeDisabled()
  expect(button).toHaveAttribute('aria-describedby', notice.id)
})

test('an ingest refused for missing ATT&CK data brings up the notice with its update button', async () => {
  let present = true
  mockApi({
    'GET /api/settings': () => settings(present, true), 'GET /api/documents': [], 'GET /api/jobs': [],
    'POST /api/ingest': () => {
      present = false
      return new Response(JSON.stringify({ error: 'ATT&CK data is missing; run the ATT&CK update first (Settings → Update ATT&CK)' }), { status: 409 })
    },
  })
  const { queryClient } = renderWithProviders(<DocumentsPage />)
  await userEvent.upload(screen.getByLabelText(/files to ingest/i), new File(['x'], 'a.txt', { type: 'text/plain' }))
  await userEvent.click(screen.getByRole('button', { name: 'Ingest 1 file(s)' }))
  const notice = await screen.findByRole('region', { name: 'Finish setup' })
  expect(within(notice).getByRole('button', { name: 'Update ATT&CK' })).toBeInTheDocument()
  // Once the data is back, the refusal is stale: it does not come back with the enabled form.
  present = true
  await act(() => queryClient.invalidateQueries({ queryKey: ['settings'] }))
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Finish setup' })).not.toBeInTheDocument())
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})

// -- supplying a document the collector could not fetch --------------------------------------

const FAILED = {
  id: 8, title: 'Advisory that could not be fetched', publisher: 'CISA', stage: 'failed',
  published_at: null, retrieved_at: '2025-01-11T10:00:00+00:00',
  failure_reason: 'HTTP 403 for https://www.cisa.gov/advisory', location: 'https://www.cisa.gov/advisory',
}

const failedRoutes = (extra: Record<string, unknown> = {}) => ({
  'GET /api/documents': [FAILED],
  'GET /api/settings': { attack: { present: true }, claude: { found: true }, config: {}, home: 'C:/argus' },
  'GET /api/jobs': [],
  ...extra,
})

test('a failed document offers the way out of retrying, not just another retry', async () => {
  mockApi(failedRoutes())
  renderWithProviders(<DocumentsPage />)

  // Retry is still there for the transient cases; the upload is for the refusals that stay.
  expect(await screen.findByRole('button', { name: 'Retry' })).toBeInTheDocument()
  const upload = screen.getByRole('button', { name: 'Upload the file' })
  // The affordance explains itself: the operator has to know the document is repaired in place.
  expect(upload).toHaveAttribute('title', expect.stringContaining('same document'))
})

test('supplying a file posts it to the document it repairs', async () => {
  const posted: string[] = []
  mockApi(failedRoutes({
    'POST /api/documents/8/supply': (init: RequestInit, url: string) => {
      posted.push(url)
      expect(init.body).toBeInstanceOf(FormData)
      return { job_id: 'job-supply-1' }
    },
  }))
  renderWithProviders(<DocumentsPage />)

  await userEvent.click(await screen.findByRole('button', { name: 'Upload the file' }))
  const picker = screen.getByLabelText(/choose the saved page/i)
  await userEvent.upload(picker, new File(['<html><body>saved</body></html>'], 'saved.html', { type: 'text/html' }))

  // Posted to THAT document, so the row — and its investigation links — are what gets repaired.
  await waitFor(() => expect(posted).toEqual(['/api/documents/8/supply']))
  expect(await screen.findByText(/analysing your file/i)).toBeInTheDocument()
})

test('a refused upload says why, where the operator is looking', async () => {
  mockApi(failedRoutes({
    'POST /api/documents/8/supply': () =>
      new Response(JSON.stringify({ error: 'saved.html exceeds the size limit' }), { status: 400 }),
  }))
  renderWithProviders(<DocumentsPage />)

  await userEvent.click(await screen.findByRole('button', { name: 'Upload the file' }))
  await userEvent.upload(
    screen.getByLabelText(/choose the saved page/i),
    new File(['x'], 'saved.html', { type: 'text/html' }),
  )

  expect(await screen.findByRole('alert')).toHaveTextContent(/exceeds the size limit/)
})

test('a refused upload leaves the control ready for the same file again', async () => {
  let attempts = 0
  mockApi(failedRoutes({
    'POST /api/documents/8/supply': () => {
      attempts += 1
      return new Response(JSON.stringify({ error: 'saved.html exceeds the size limit' }), { status: 400 })
    },
  }))
  renderWithProviders(<DocumentsPage />)

  await userEvent.click(await screen.findByRole('button', { name: 'Upload the file' }))
  const file = new File(['x'], 'saved.html', { type: 'text/html' })
  await userEvent.upload(screen.getByLabelText(/choose the saved page/i), file)
  expect(await screen.findByRole('alert')).toBeInTheDocument()

  // The finding: the native input kept the FileList, so re-picking the SAME file after fixing
  // the cause fired no change event and the control silently did nothing.
  await userEvent.upload(screen.getByLabelText(/choose the saved page/i), file)
  await waitFor(() => expect(attempts).toBe(2))
})
