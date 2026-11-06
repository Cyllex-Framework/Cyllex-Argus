import { screen } from '@testing-library/react'
import { InvestigationReport } from './InvestigationReport'
import { mockApi, renderWithProviders } from '../../test/utils'

const ENTITY = { id: 'is--1', stix_type: 'intrusion-set', name: 'Scattered Spider', external_id: 'G1015', attack: true, aliases: [{ alias: 'UNC3944', origin: 'attack' }] }
const EMPTY_USAGE = { by_stage: {}, total: { calls: 2, input_tokens: 10, output_tokens: 5, total_tokens: 15, cost_usd: 0 } }
const INVESTIGATION = {
  id: 12, target: 'Scattered Spider', state: 'finished', started_at: '2026-10-20T10:00:00Z',
  finished_at: '2026-10-20T10:04:00Z', failure_reason: null, counts: { validated: 2 }, token_usage: EMPTY_USAGE,
}
const SUMMARY = {
  summary: 'Scattered Spider is a financially motivated intrusion set that social-engineers help desks.',
  generated_at: '2026-10-20T10:04:30+00:00', stale: false, fact_count: 2,
  written_from_fact_count: 2, prompt_version: 'summary-v1', model: 'claude-sonnet-5-5', can_generate: true,
}

const routes = (summary: unknown) => ({
  'GET /api/investigations/12/dashboard': { investigation: INVESTIGATION, entity: ENTITY, attack_matrix: { tactics: [] } },
  'GET /api/investigations/12': { ...INVESTIGATION, stage_counts: {}, failures: [], documents: [] },
  'GET /api/investigations/12/trace': { events: [], cost: null },
  'GET /api/threats/is--1': { entity: { ...ENTITY, label: ENTITY.name }, aliases: [], facts: [] },
  'GET /api/threats/is--1/summary': summary,
  'GET /api/threats/is--1/campaigns': { campaigns: [] },
})

const render = () =>
  renderWithProviders(<InvestigationReport />, { route: '/investigations/12/report', path: '/investigations/:id/report' })

test('the dossier opens on the executive summary, with how and when it was written', async () => {
  mockApi(routes(SUMMARY))
  render()
  expect(await screen.findByRole('heading', { name: 'Executive summary' })).toBeInTheDocument()
  expect(screen.getByText(/social-engineers help desks/)).toBeInTheDocument()
  expect(screen.getByText(/Written by Argus from the consolidated assessments/)).toBeInTheDocument()
  // It leads the contents list, ahead of the alias section the dossier used to open on.
  const toc = document.querySelector('.report-toc')
  expect(toc?.textContent).toMatch(/Executive summary.*Aliases/s)
})

test('no cached summary: no empty heading and no promise of one in the contents', async () => {
  mockApi(routes({ ...SUMMARY, summary: null, generated_at: null, written_from_fact_count: null }))
  render()
  // Wait for a section that always renders, so the absence below is not just "not loaded yet".
  expect(await screen.findByRole('heading', { name: 'Aliases' })).toBeInTheDocument()
  expect(screen.queryByRole('heading', { name: 'Executive summary' })).not.toBeInTheDocument()
  expect(screen.queryByText('Executive summary')).not.toBeInTheDocument()
})

test('a stale summary prints, and says the sections below are the current ones', async () => {
  mockApi(routes({ ...SUMMARY, stale: true, fact_count: 9 }))
  render()
  expect(await screen.findByText(/the sections below are current, this summary is not/)).toBeInTheDocument()
})

test('the cover states the evidence base, and names what could not be read', async () => {
  mockApi({
    ...routes(SUMMARY),
    'GET /api/investigations/12/dashboard': {
      investigation: { ...INVESTIGATION, counts: { validated: 25, failed: 15, irrelevant: 2 } },
      entity: ENTITY, attack_matrix: { tactics: [] },
    },
  })
  render()

  const meta = await screen.findByText('Evidence base')
  expect(meta.closest('div')?.textContent).toMatch(/25 of 42 documents read/)
  // And the part a reader cannot infer from the findings: what the gap does not mean.
  expect(screen.getByText(/Coverage limitation/)).toBeInTheDocument()
  expect(screen.getByText(/may be absent from the reporting, or present only/)).toBeInTheDocument()
})

test('a complete collection makes no claim about gaps it does not have', async () => {
  mockApi({
    ...routes(SUMMARY),
    'GET /api/investigations/12/dashboard': {
      investigation: { ...INVESTIGATION, counts: { validated: 25 } },
      entity: ENTITY, attack_matrix: { tactics: [] },
    },
  })
  render()

  const meta = await screen.findByText('Evidence base')
  expect(meta.closest('div')?.textContent).toMatch(/25 of 25 documents read/)
  expect(screen.queryByText(/Coverage limitation/)).not.toBeInTheDocument()
})
