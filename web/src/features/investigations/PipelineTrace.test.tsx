import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { PipelineEvent } from '../../api/types'
import { mockApi, renderWithProviders } from '../../test/utils'
import { PipelineTrace } from './PipelineTrace'

const ev = (over: Partial<PipelineEvent>): PipelineEvent => ({
  id: 1, document_id: 7, stage: 'collector', decision: 'collected', reason: null, created_at: '2026-09-29T14:31:02Z',
  duration_ms: null, usage: null, has_raw: false, ...over,
})
const USAGE = { input_tokens: 10, output_tokens: 5, model: 'sonnet', duration_ms: 900 }
const EVENTS = [
  ev({ id: 1, document_id: null, stage: 'pipeline', decision: 'failed', reason: 'boom' }),
  ev({ id: 2 }),
  ev({ id: 3, stage: 'triage', decision: 'triaged-in', reason: 'about the target', usage: USAGE, has_raw: true }),
  ev({ id: 4, stage: 'analyst', decision: 'no-claims', usage: USAGE, has_raw: false }),
  ev({ id: 5, document_id: 8, stage: 'validator', decision: 'rejected', reason: 'no quote' }),
]
const TRACE = 'GET /api/investigations/12/trace'

function setup(routes: Record<string, unknown> = {}, events = EVENTS) {
  const fetchMock = mockApi({ [TRACE]: { cost: null, documents: [{ id: 7, title: 'Scattered Spider report' }], events }, ...routes })
  renderWithProviders(<PipelineTrace investigationId="12" />)
  return fetchMock
}

test('collapsed by default with the event count, expands into groups', async () => {
  setup()
  const toggle = await screen.findByRole('button', { name: /5 events/ })
  expect(toggle).toHaveAttribute('aria-expanded', 'false')
  expect(screen.queryByText('Scattered Spider report')).not.toBeInTheDocument()
  await userEvent.click(toggle)
  expect(toggle).toHaveAttribute('aria-expanded', 'true')
  expect(toggle).toHaveAttribute('aria-controls', expect.stringContaining('pipeline-trace-body'))
  const headings = screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent)
  expect(headings).toEqual(['General', 'Scattered Spider report', 'Document #8'])
  expect(screen.getByText('triaged in')).toBeInTheDocument()
  expect(screen.getByText('(about the target)')).toBeInTheDocument()
  expect(screen.getByText('no-claims')).toBeInTheDocument()
  expect(screen.getByText('failed')).toHaveClass('text-red-400')
  expect(screen.getByText('rejected')).toHaveClass('text-red-400')
  expect(screen.getByText('collected').closest('li')).not.toHaveTextContent('(')
})

test('Show raw only for LLM events with raw text; fetch, show, hide', async () => {
  setup({ 'GET /api/investigations/12/trace/3/raw': { prompt: 'the prompt', response: 'the response' } })
  await userEvent.click(await screen.findByRole('button', { name: /5 events/ }))
  expect(screen.getAllByRole('button', { name: 'Show raw' })).toHaveLength(1)
  await userEvent.click(screen.getByRole('button', { name: 'Show raw' }))
  expect(await screen.findByText('the prompt')).toBeInTheDocument()
  expect(screen.getByText('the response')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Hide' }))
  expect(screen.queryByText('the prompt')).not.toBeInTheDocument()
})

test('a raw text error shows inline as an alert', async () => {
  setup()
  await userEvent.click(await screen.findByRole('button', { name: /5 events/ }))
  await userEvent.click(screen.getByRole('button', { name: 'Show raw' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('no mock for')
})

test('delete: cancel keeps it, confirm sends DELETE and refetches', async () => {
  let events = EVENTS
  const fetchMock = mockApi({
    [TRACE]: () => ({ cost: null, events }),
    'DELETE /api/investigations/12/trace': () => { events = []; return { deleted: 5 } },
  })
  renderWithProviders(<PipelineTrace investigationId="12" />)
  const open = await screen.findByRole('button', { name: 'Delete pipeline trace' })
  await userEvent.click(open)
  expect(screen.getByRole('dialog')).toHaveTextContent('The investigation itself and its facts stay.')
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(fetchMock.mock.calls.some(([, init]) => (init as RequestInit | undefined)?.method === 'DELETE')).toBe(false)

  await userEvent.click(open)
  await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  const call = fetchMock.mock.calls.find(([, init]) => (init as RequestInit | undefined)?.method === 'DELETE')
  expect(new Headers((call![1] as RequestInit).headers).get('X-Argus-CSRF')).toBe('1')
  expect(await screen.findByRole('button', { name: /0 events/ })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Delete pipeline trace' })).toBeDisabled()
})

test('delete button is disabled with no events', async () => {
  setup({}, [])
  expect(await screen.findByRole('button', { name: 'Delete pipeline trace' })).toBeDisabled()
})

test('a refused event reads as an amber safety-policy block, not a red failure, with the fix', async () => {
  setup({}, [ev({
    id: 9, stage: 'analyst', decision: 'refused',
    reason: "Blocked by the model's safety policy (cyber). Try a different model (e.g. Opus 4.6 or Haiku 5.5).",
  })])
  await userEvent.click(await screen.findByRole('button', { name: /1 event/ }))
  const label = screen.getByText('blocked by safety policy')
  expect(label).toHaveClass('text-amber-400')
  expect(label).not.toHaveClass('text-red-400')
  // The actionable fix (which model to switch to) is visible to the operator.
  expect(screen.getByText(/Opus 4\.6 or Haiku 5\.5/)).toBeInTheDocument()
})
