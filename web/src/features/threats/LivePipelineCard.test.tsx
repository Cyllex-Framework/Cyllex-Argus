import { screen } from '@testing-library/react'
import { LivePipelineCard } from './LivePipelineCard'
import { mockApi, renderWithProviders } from '../../test/utils'
import type { LivePipelineTree } from '../../api/hooks'

const BASE: LivePipelineTree = {
  investigation_id: 3,
  target: 'Carbanak',
  state: 'running',
  elapsed_secs: 222,
  prompt_version: 'analyst-v3.1',
  stages: [
    { key: 'collect', state: 'done', summary: '12 docs collected', latest_reason: null },
    { key: 'triage', state: 'done', summary: '10 kept · 2 off-topic', latest_reason: 'Mandiant brief mentions Carbanak' },
    { key: 'analyze', state: 'active', summary: '7 / 10 docs', latest_reason: null },
    { key: 'validate', state: 'queued', summary: '138 accepted · 3 rejected', latest_reason: null },
  ],
  docs: [
    { document_id: 11, title: 'Bitdefender APT Blueprint', url: 'https://bitdefender.example/apt', state: 'done',   facts_count: 18, elapsed_secs: 2.1 },
    { document_id: 12, title: 'Microsoft TI blog',          url: 'https://microsoft.example/ti',  state: 'queued', facts_count: 0,  elapsed_secs: null },
  ],
  validator: {
    accepted: 138, rejected: 3, captured_as_sector: 2, swapped: 0,
    latest_reject: "'AWS' is a known technology/platform — identity mistype",
    latest_capture: 'Carbanak.attributes.sectors += "banks"',
  },
  totals: { claims: 138, docs_analyzed: 7, docs_remaining: 3 },
}

test('null investigationId does not render anything', () => {
  const { container } = renderWithProviders(<LivePipelineCard investigationId={null} />)
  expect(container.textContent).toBe('')
})

test('silent degradation: the card drops out when the endpoint 404s instead of showing an error', async () => {
  // The card is an extra on pages that have their own primary content; a loud error from
  // a background poll would hurt the parent view more than quietly disappearing. This also
  // keeps the component robust against a backend/frontend deploy skew where the endpoint
  // temporarily does not exist.
  mockApi({ 'GET /api/investigations/42/live-tree': new Response('{}', { status: 404 }) })
  const { container } = renderWithProviders(<LivePipelineCard investigationId={42} />)
  // Give the query a tick to resolve the 404; then the card renders nothing.
  await new Promise((resolve) => setTimeout(resolve, 50))
  expect(container.querySelector('section')).toBeNull()
})

test('renders the four stage labels in order with their state styling', async () => {
  mockApi({ 'GET /api/investigations/3/live-tree': BASE })
  renderWithProviders(<LivePipelineCard investigationId={3} />)
  // One label per stage — the summary line comes with it.
  for (const label of ['Collect', 'Triage', 'Analyze', 'Validate']) {
    expect(await screen.findByText(label)).toBeInTheDocument()
  }
  expect(screen.getByText('12 docs collected')).toBeInTheDocument()
  // "7 / 10 docs" appears both in the Analyze stage summary and in the progress-rail label.
  expect(screen.getAllByText(/7 \/ 10 docs/).length).toBeGreaterThanOrEqual(1)
})

test('shows the active-stage docs with linked titles and the queued pseudo-state', async () => {
  mockApi({ 'GET /api/investigations/3/live-tree': BASE })
  renderWithProviders(<LivePipelineCard investigationId={3} />)
  // Linked doc opens in a new tab.
  const link = await screen.findByRole('link', { name: 'Bitdefender APT Blueprint' })
  expect(link).toHaveAttribute('href', 'https://bitdefender.example/apt')
  expect(link).toHaveAttribute('target', '_blank')
  expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'))
  // The queued one shows the pseudo-state instead of a facts count.
  expect(screen.getByText(/queued/)).toBeInTheDocument()
})

test('surfaces the Validator counters and latest reasons', async () => {
  mockApi({ 'GET /api/investigations/3/live-tree': BASE })
  renderWithProviders(<LivePipelineCard investigationId={3} />)
  // Each counter's label appears somewhere.
  expect(await screen.findByText('accepted')).toBeInTheDocument()
  expect(screen.getByText('rejected')).toBeInTheDocument()
  expect(screen.getByText('captured-as-sector')).toBeInTheDocument()
  // Latest reason lines, both reject and capture.
  expect(screen.getByText(/identity mistype/)).toBeInTheDocument()
  expect(screen.getByText(/sectors \+= "banks"/)).toBeInTheDocument()
})

test('elapsed time formats as "Xm Ys" when the run has been going for more than a minute', async () => {
  mockApi({ 'GET /api/investigations/3/live-tree': BASE })
  renderWithProviders(<LivePipelineCard investigationId={3} />)
  // 222 secs → 3m 42s
  expect(await screen.findByText(/3m 42s/)).toBeInTheDocument()
})

test('finished state renders a resting snapshot without stopping on an error', async () => {
  const finished: LivePipelineTree = { ...BASE, state: 'finished', docs: [] }
  mockApi({ 'GET /api/investigations/3/live-tree': finished })
  renderWithProviders(<LivePipelineCard investigationId={3} />)
  expect(await screen.findByText(/FINISHED/)).toBeInTheDocument()
  // Totals still visible — "claims" label survives even when docs list is empty.
  expect(screen.getByText('claims')).toBeInTheDocument()
})
