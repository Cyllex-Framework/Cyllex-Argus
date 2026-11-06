import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'
import type { DashboardEntity, DashboardInvestigation } from '../../api/types'
import { mockApi, renderWithProviders } from '../../test/utils'
import { InvestigationHeader } from './InvestigationHeader'

const downloadFile = vi.hoisted(() => vi.fn())
vi.mock('../../api/download', () => ({ downloadFile }))

const ENTITY: DashboardEntity = {
  id: 'is--1', stix_type: 'intrusion-set', name: 'Scattered Spider', external_id: 'G1015', attack: true,
  aliases: [{ alias: 'Octo Tempest', origin: 'source' }, { alias: 'UNC3944', origin: 'attack' }],
}

const EMPTY_USAGE = { by_stage: {}, total: { calls: 0, input_tokens: 0, output_tokens: 0, total_tokens: 0, cost_usd: 0 } }

function investigation(over: Partial<DashboardInvestigation> = {}): DashboardInvestigation {
  return {
    id: 12, target: 'Octo Tempest', state: 'finished', started_at: '2026-09-29T14:31:02Z',
    finished_at: '2026-09-29T14:33:47Z', failure_reason: null, counts: { validated: 2, irrelevant: 1, failed: 1 },
    token_usage: EMPTY_USAGE, ...over,
  }
}

beforeEach(() => {
  downloadFile.mockReset()
  downloadFile.mockResolvedValue(undefined)
  mockApi({})
})

test('finished: entity name, type, external id, aliases, green pill and counts', () => {
  renderWithProviders(<InvestigationHeader investigation={investigation()} entity={ENTITY} runningJobId={null} />)
  expect(screen.getByRole('heading', { name: 'Scattered Spider' })).toBeInTheDocument()
  expect(screen.getByText(/intrusion-set/)).toBeInTheDocument()
  expect(screen.getByText(/G1015/)).toBeInTheDocument()
  expect(screen.getByText('Octo Tempest')).toBeInTheDocument()
  expect(screen.getByText('UNC3944')).toBeInTheDocument()
  expect(screen.getByText('finished')).toHaveClass('text-green-400')
  expect(screen.getByText(/2 validated/)).toBeInTheDocument()
  expect(screen.getByText(/1 irrelevant/)).toBeInTheDocument()
  expect(screen.getByText(/1 failed/)).toBeInTheDocument()
})

test('running: yellow pill, documents analyzed caption and the job panel', () => {
  renderWithProviders(<InvestigationHeader investigation={investigation({ state: 'running', finished_at: null })} entity={ENTITY} runningJobId="job-1" />)
  expect(screen.getByText('running')).toHaveClass('text-yellow-400')
  expect(screen.getByText(/Investigation running/)).toHaveTextContent('4 documents analyzed')
  expect(screen.getByText('Waiting for the job to start...')).toBeInTheDocument()
})

test('no job panel without a running job id', () => {
  renderWithProviders(<InvestigationHeader investigation={investigation()} entity={ENTITY} runningJobId={null} />)
  expect(screen.queryByText('Progress')).not.toBeInTheDocument()
})

test('failed: red pill and the failure reason', () => {
  renderWithProviders(<InvestigationHeader investigation={investigation({ state: 'failed', failure_reason: 'Claude CLI crashed' })} entity={ENTITY} runningJobId={null} />)
  expect(screen.getByText('failed', { selector: 'span.text-red-400' })).toBeInTheDocument()
  expect(screen.getByText('Claude CLI crashed')).toBeInTheDocument()
})

test('unresolved + running: Resolving target heading, the target as context, no export buttons', () => {
  renderWithProviders(<InvestigationHeader investigation={investigation({ state: 'running' })} entity={null} runningJobId={null} />)
  expect(screen.getByRole('heading', { name: 'Resolving target…' })).toBeInTheDocument()
  expect(screen.getByText(/Octo Tempest/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /Markdown/ })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /STIX/ })).not.toBeInTheDocument()
})

test('unresolved + finished: heading falls back to the raw target string, NOT "Resolving target…"', () => {
  // The resolver finished without picking an entity (long descriptive target did not map to a
  // single catalog entity). Showing "Resolving target…" would be a UX lie — the run is done.
  const target = 'Midnight Blizzard Microsoft January 2024 OAuth corporate email breach'
  renderWithProviders(<InvestigationHeader investigation={investigation({ state: 'finished', target })} entity={null} runningJobId={null} />)
  expect(screen.getByRole('heading', { name: target })).toBeInTheDocument()
  expect(screen.queryByRole('heading', { name: 'Resolving target…' })).not.toBeInTheDocument()
})

test('unresolved + paused: heading uses the raw target too', () => {
  const target = 'Operation Weekend Investigation'
  renderWithProviders(<InvestigationHeader investigation={investigation({ state: 'paused', target })} entity={null} runningJobId={null} />)
  expect(screen.getByRole('heading', { name: target })).toBeInTheDocument()
  expect(screen.queryByRole('heading', { name: 'Resolving target…' })).not.toBeInTheDocument()
})

test('unresolved + failed: heading uses the raw target too', () => {
  const target = 'Some target that errored out'
  renderWithProviders(<InvestigationHeader investigation={investigation({ state: 'failed', target })} entity={null} runningJobId={null} />)
  expect(screen.getByRole('heading', { name: target })).toBeInTheDocument()
})

test('export menu downloads each format through downloadFile', async () => {
  renderWithProviders(<InvestigationHeader investigation={investigation()} entity={ENTITY} runningJobId={null} />)
  // Export is now a dropdown — open it, then click each item. The menu does not close on
  // item click so the three downloads can be fired in sequence as the operator would.
  await userEvent.click(screen.getByRole('button', { name: /^Export/ }))
  await userEvent.click(screen.getByRole('menuitem', { name: 'Markdown' }))
  await userEvent.click(screen.getByRole('menuitem', { name: 'Markdown + AI summary' }))
  await userEvent.click(screen.getByRole('menuitem', { name: 'STIX 2.1' }))
  await waitFor(() => expect(downloadFile).toHaveBeenCalledTimes(3))
  expect(downloadFile).toHaveBeenNthCalledWith(1, '/api/threats/is--1/export?format=markdown', 'threat.md')
  expect(downloadFile).toHaveBeenNthCalledWith(2, '/api/threats/is--1/export?format=markdown&summary=1', 'threat.md')
  expect(downloadFile).toHaveBeenNthCalledWith(3, '/api/threats/is--1/export?format=stix', 'threat.stix.json')
  expect(document.querySelector('a[href^="/api"]')).toBeNull()
})

describe('cost line', () => {
  const trace = (cost: unknown) => ({ 'GET /api/investigations/12/trace': { cost, events: [] } })

  test('formats cost, tokens and LLM time', async () => {
    mockApi(trace({ input_tokens: 12345, output_tokens: 6789, usd: 1.316, duration_ms: 47000 }))
    renderWithProviders(<InvestigationHeader investigation={investigation()} entity={ENTITY} runningJobId={null} />)
    expect(await screen.findByText('Cost: $1.32 · 12,345 in / 6,789 out tokens · 47 s LLM time')).toBeInTheDocument()
  })

  test('short durations get a decimal and large costs one', async () => {
    mockApi(trace({ input_tokens: 1, output_tokens: 2, usd: 12.34, duration_ms: 4250 }))
    renderWithProviders(<InvestigationHeader investigation={investigation()} entity={ENTITY} runningJobId={null} />)
    expect(await screen.findByText('Cost: $12.3 · 1 in / 2 out tokens · 4.3 s LLM time')).toBeInTheDocument()
  })

  test('null cost reads not recorded', async () => {
    mockApi(trace(null))
    renderWithProviders(<InvestigationHeader investigation={investigation()} entity={ENTITY} runningJobId={null} />)
    expect(await screen.findByText('Cost: not recorded')).toBeInTheDocument()
  })

  test('no cost line when the trace fails to load', async () => {
    mockApi({})
    renderWithProviders(<InvestigationHeader investigation={investigation()} entity={ENTITY} runningJobId={null} />)
    await screen.findByText('finished')
    expect(screen.queryByText(/^Cost:/)).not.toBeInTheDocument()
  })
})

test('the metrics row reads in threat language, with the machine telemetry demoted to a footnote', async () => {
  // Three of the five tiles used to be LLM time / Tokens / Cost — machine figures in the
  // second-most prominent slot on the page, above what the run actually learned. The numbers
  // are still here, on the small mono line under the row.
  mockApi({
    'GET /api/threats/is--1': {
      entity: { id: 'is--1', stix_type: 'intrusion-set', name: 'Scattered Spider', external_id: 'G1015', attack: true, label: 'Scattered Spider' },
      aliases: [], facts: [1, 2, 3].map(() => ({
        subject: { id: 'is--1', stix_type: 'intrusion-set', name: 'Scattered Spider', external_id: null, attack: true, label: 'Scattered Spider' },
        predicate: 'uses',
        object: { id: 'ap--1', stix_type: 'attack-pattern', name: 'Phishing', external_id: 'T1566', attack: true, label: 'Phishing' },
        status: 'corroborated', confidence: 60, admiralty: 'B2', first_seen: null, last_seen: null,
        source_count: 2, citations: [],
      })),
    },
  })
  const usage = { by_stage: {}, total: { calls: 3, input_tokens: 12_000, output_tokens: 3_000, total_tokens: 15_000, cost_usd: 0.42 } }
  renderWithProviders(
    <InvestigationHeader investigation={investigation({ token_usage: usage })} entity={ENTITY}
      runningJobId={null} techniques={7} />,
  )
  const row = screen.getByRole('group', { name: 'What this run learned' })
  expect(row).toHaveTextContent('Validated')
  expect(row).toHaveTextContent('Failed')
  expect(row).toHaveTextContent('Techniques')
  expect(row).toHaveTextContent('7')
  expect(row).toHaveTextContent('Facts')
  await waitFor(() => expect(row).toHaveTextContent('3'))
  // Telemetry kept, visibly secondary.
  expect(row).not.toHaveTextContent('Cost')
  expect(screen.getByText(/15k tokens/)).toHaveTextContent('$0.42')
})

test('techniques and facts read as unknown rather than zero before they are loaded', () => {
  renderWithProviders(<InvestigationHeader investigation={investigation()} entity={null} runningJobId={null} />)
  const dashes = screen.getAllByText('\u2014')
  expect(dashes.length).toBeGreaterThanOrEqual(2)
})
