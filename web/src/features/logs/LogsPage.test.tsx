import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { LogEvent, LogJob, LogsResponse } from '../../api/types'
import { mockApi, renderWithProviders } from '../../test/utils'
import { LogsPage } from './LogsPage'

const job = (over: Partial<LogJob>): LogJob => ({
  id: 'j1', kind: 'investigate', state: 'finished', started_at: '2026-09-30T10:00:00+00:00',
  finished_at: '2026-09-30T10:00:05+00:00', message: null, duration_ms: 5000, events_count: 3, ...over,
})
const event = (over: Partial<LogEvent>): LogEvent => ({
  id: 1, investigation_id: 12, investigation_target: 'Scattered Spider', document_id: 7, document_title: 'Mandiant report',
  stage: 'collector', decision: 'collected', reason: null, created_at: '2026-09-30T10:00:01+00:00',
  duration_ms: null, input_tokens: null, output_tokens: null, cost_usd: null, ...over,
})
const JOBS = [
  job({ id: 'j1', kind: 'investigate' }),
  job({ id: 'j2', kind: 'attack_update', state: 'failed', message: 'RuntimeError: boom', duration_ms: 400 }),
]
const EVENTS = [
  event({ id: 1 }),
  event({ id: 2, stage: 'analyst', decision: 'analysed', input_tokens: 1000, output_tokens: 500 }),
  event({ id: 3, stage: 'validator', decision: 'rejected', reason: 'no quote', document_id: null }),
]

function setup(logs: (url: string) => LogsResponse = () => ({ jobs: JOBS, events: EVENTS })) {
  const fetchMock = mockApi({ 'GET /api/logs': (_init: RequestInit, url: string) => logs(url), 'GET /api/jobs': [] })
  renderWithProviders(<LogsPage />)
  return fetchMock
}

test('renders the jobs table and the agent groups with a legend', async () => {
  setup()
  const table = await screen.findByRole('table')
  expect(within(table).getByText('ATT&CK update')).toBeInTheDocument()
  expect(within(table).getByText('RuntimeError: boom')).toBeInTheDocument()
  expect(within(table).getByText('failed')).toBeInTheDocument()
  expect(within(table).getByText('5.0 s')).toBeInTheDocument()
  expect(screen.getByRole('heading', { level: 2, name: 'Jobs' })).toBeInTheDocument()
  expect(screen.getByRole('heading', { level: 2, name: 'Agent events' })).toBeInTheDocument()
  expect(screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent?.replace(/\s*\(\d+\)/, ''))).toEqual(
    ['Collector', 'Triage', 'Analyst', 'Validator', 'Pipeline'])
  expect(screen.getByLabelText('What each agent does')).toHaveTextContent('Checks each claim against its quote')
})

test('agent groups list their events with links, reasons and tokens', async () => {
  setup()
  const collector = await screen.findByRole('region', { name: 'Collector' })
  expect(within(collector).getByRole('link', { name: 'Scattered Spider' })).toHaveAttribute('href', '/investigations/12/dashboard')
  expect(within(collector).getByRole('link', { name: 'Mandiant report' })).toHaveAttribute('href', '/documents/7')
  expect(within(screen.getByRole('region', { name: 'Analyst' })).getByText('1,500 tokens')).toBeInTheDocument()
  const validator = screen.getByRole('region', { name: 'Validator' })
  expect(within(validator).getByText('(no quote)')).toBeInTheDocument()
  expect(within(validator).queryByRole('link', { name: /Mandiant/ })).not.toBeInTheDocument()
  expect(within(screen.getByRole('region', { name: 'Triage' })).getByText('No events.')).toBeInTheDocument()
})

test('the kind filter narrows the jobs list', async () => {
  const fetchMock = setup((url) => {
    const kind = new URL(url, 'http://x').searchParams.get('kind')
    return { jobs: kind ? JOBS.filter((j) => j.kind === kind) : JOBS, events: EVENTS }
  })
  await screen.findByText('ATT&CK update', { selector: 'td' })
  await userEvent.selectOptions(screen.getByLabelText('Filter by kind'), 'investigate')
  await screen.findByText('Investigate', { selector: 'td' })
  expect(screen.queryByText('ATT&CK update', { selector: 'td' })).not.toBeInTheDocument()
  expect(fetchMock.mock.calls.some(([url]) => String(url).includes('kind=investigate'))).toBe(true)
})

test('the time range and state filters are sent to the server', async () => {
  const fetchMock = setup()
  await screen.findByRole('table')
  await userEvent.selectOptions(screen.getByLabelText('Filter by state'), 'failed')
  await userEvent.selectOptions(screen.getByLabelText('Time range'), 'all')
  await screen.findByRole('table')
  const urls = fetchMock.mock.calls.map(([url]) => String(url)).filter((u) => u.startsWith('/api/logs'))
  expect(urls.some((u) => u.includes('state=failed'))).toBe(true)
  expect(urls.at(-1)).not.toContain('since=')
  expect(urls[0]).toContain('since=') // the default is the last 24 h
})

test('empty state when there is no data', async () => {
  setup(() => ({ jobs: [], events: [] }))
  expect(await screen.findByText(/No jobs match these filters/)).toBeInTheDocument()
  expect(screen.getByText(/No agent events in this time range/)).toBeInTheDocument()
  expect(screen.queryByRole('table')).not.toBeInTheDocument()
})
