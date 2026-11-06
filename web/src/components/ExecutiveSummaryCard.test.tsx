import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ExecutiveSummaryCard } from './ExecutiveSummaryCard'
import { mockApi, renderWithProviders } from '../test/utils'

const THREAT = 'intrusion-set--abc'
const PATH = `GET /api/threats/${THREAT}/summary`
const WRITE = `POST /api/threats/${THREAT}/summary`

const body = (overrides: Record<string, unknown> = {}) => ({
  summary: 'Scattered Spider is a financially motivated intrusion set.',
  generated_at: '2026-10-20T10:00:00+00:00',
  stale: false,
  fact_count: 12,
  written_from_fact_count: 12,
  prompt_version: 'summary-v1',
  model: 'claude-sonnet-5-5',
  can_generate: true,
  ...overrides,
})

const render = () => renderWithProviders(<ExecutiveSummaryCard threatId={THREAT} />)

test('shows the prose verdict with how it was written', async () => {
  mockApi({ [PATH]: body() })
  render()
  expect(await screen.findByText(/financially motivated intrusion set/)).toBeInTheDocument()
  expect(screen.getByText(/from 12 facts/)).toBeInTheDocument()
  expect(screen.getByText(/claude-sonnet-5-5/)).toBeInTheDocument()
})

test('reading the summary never POSTs — a page load must not bill the operator', async () => {
  const fetchMock = mockApi({ [PATH]: body() })
  render()
  await screen.findByText(/financially motivated/)
  expect(fetchMock.mock.calls.every(([, init]) => (init?.method ?? 'GET') === 'GET')).toBe(true)
})

test('a stale summary stays readable and says how far behind it is', async () => {
  mockApi({ [PATH]: body({ stale: true, fact_count: 15, written_from_fact_count: 12 }) })
  render()
  expect(await screen.findByText(/financially motivated/)).toBeInTheDocument()
  expect(screen.getByText(/3 new facts since this was written/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Update' })).toBeInTheDocument()
})

test('no summary yet: offers to write one, and shows it once written', async () => {
  let written = false
  mockApi({
    [PATH]: () => (written ? body() : body({ summary: null, generated_at: null, written_from_fact_count: null })),
    [WRITE]: () => {
      written = true
      return body()
    },
  })
  render()
  await userEvent.click(await screen.findByRole('button', { name: 'Write summary' }))
  expect(await screen.findByText(/financially motivated/)).toBeInTheDocument()
})

test('a threat with no facts says so instead of offering a button that cannot work', async () => {
  mockApi({ [PATH]: body({ summary: null, fact_count: 0, written_from_fact_count: null, can_generate: false }) })
  render()
  expect(await screen.findByText(/investigate this threat to collect quote-backed facts/i)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Write summary' })).not.toBeInTheDocument()
})

test('a provider failure is reported in place, with the server message', async () => {
  mockApi({
    [PATH]: body({ summary: null, written_from_fact_count: null }),
    [WRITE]: () => new Response(JSON.stringify({ error: 'usage limit reached' }), { status: 503 }),
  })
  render()
  await userEvent.click(await screen.findByRole('button', { name: 'Write summary' }))
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('usage limit reached'))
})

test('a long summary is clamped to a readable headline, with the rest one click away', async () => {
  // Real shape: 139 facts on Scattered Spider produced 352 words in a single paragraph.
  const wall = `Scattered Spider is a financially motivated intrusion set. ${'Corroborated tradecraft spans voice phishing, impersonation and MFA fatigue. '.repeat(8)}`
  mockApi({ [PATH]: body({ summary: wall }) })
  render()
  const prose = await screen.findByText(/financially motivated intrusion set/)
  expect(prose.className).toContain('line-clamp-6')

  const toggle = screen.getByRole('button', { name: 'Show the full summary' })
  expect(toggle).toHaveAttribute('aria-expanded', 'false')
  await userEvent.click(toggle)
  expect(prose.className).not.toContain('line-clamp-6')
  expect(screen.getByRole('button', { name: 'Show less' })).toHaveAttribute('aria-expanded', 'true')
})

test('a short summary is shown whole, with no toggle to click', async () => {
  mockApi({ [PATH]: body() })
  render()
  const prose = await screen.findByText(/financially motivated intrusion set/)
  expect(prose.className).not.toContain('line-clamp')
  expect(screen.queryByRole('button', { name: /full summary/ })).not.toBeInTheDocument()
})
