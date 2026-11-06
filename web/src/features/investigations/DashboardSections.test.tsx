import { screen } from '@testing-library/react'
import { mockApi, renderWithProviders } from '../../test/utils'
import { DashboardDocuments } from './DashboardDocuments'
import { DashboardOverview } from './DashboardOverview'
import { InvestigationQuickActions } from './InvestigationQuickActions'

const ref = (id: string, name: string, type: string) => ({ id, stix_type: type, name, external_id: null, attack: true, label: name })
const fact = (object: ReturnType<typeof ref>, predicate = 'uses') => ({
  subject: ref('is--1', 'Scattered Spider', 'intrusion-set'), predicate, object, status: 'corroborated', confidence: 60,
  admiralty: 'B2', first_seen: null, last_seen: null, source_count: 2, citations: [],
})
const ENTITY = { id: 'is--1', stix_type: 'intrusion-set', name: 'Scattered Spider', external_id: 'G1015', attack: true, aliases: [{ alias: 'UNC3944', origin: 'attack' }] }
const EMPTY_USAGE = { by_stage: {}, total: { calls: 0, input_tokens: 0, output_tokens: 0, total_tokens: 0, cost_usd: 0 } }
const INVESTIGATION = { id: 12, target: 'Octo Tempest', state: 'finished', started_at: '', finished_at: null, failure_reason: null, counts: {}, token_usage: EMPTY_USAGE }

const SUMMARY = {
  summary: 'Scattered Spider is a financially motivated intrusion set.',
  generated_at: '2026-10-20T10:00:00+00:00', stale: false, fact_count: 2,
  written_from_fact_count: 2, prompt_version: 'summary-v1', model: 'claude-sonnet-5-5', can_generate: true,
}

const overviewRoutes = {
  'GET /api/settings': { attack: { present: true } },
  'GET /api/threats/is--1/summary': SUMMARY,
  'GET /api/threats/is--1': {
    entity: ref('is--1', 'Scattered Spider', 'intrusion-set'), aliases: [],
    facts: [fact(ref('ap--1', 'Phishing', 'attack-pattern')), fact(ref('m--1', 'Mimikatz', 'malware'))],
  },
}

test('overview leads with the executive summary, then the six counts', async () => {
  mockApi(overviewRoutes)
  renderWithProviders(<DashboardOverview investigation={INVESTIGATION} entity={ENTITY} attackMissing={false} />)
  expect(await screen.findByText(/financially motivated intrusion set/)).toBeInTheDocument()
  expect(await screen.findByText('Techniques')).toBeInTheDocument()
  expect(screen.getByText('Vulnerabilities')).toBeInTheDocument()
})

test('overview does not repeat the identity the page header already shows', async () => {
  // The old Overview card re-printed the entity type and every alias chip, which the page
  // header and the sidebar header also show: the same identity three times before a single
  // fact. Identity belongs to the header alone.
  mockApi(overviewRoutes)
  renderWithProviders(<DashboardOverview investigation={INVESTIGATION} entity={ENTITY} attackMissing={false} />)
  await screen.findByText(/financially motivated intrusion set/)
  expect(screen.queryByText('G1015')).not.toBeInTheDocument()
  expect(screen.queryByText('UNC3944')).not.toBeInTheDocument()
})

test('an unresolved target says why there is no summary instead of showing an empty card', async () => {
  mockApi(overviewRoutes)
  renderWithProviders(<DashboardOverview investigation={INVESTIGATION} entity={null} attackMissing={false} />)
  expect(await screen.findByText(/never resolved/)).toBeInTheDocument()
  expect(screen.getByText('Octo Tempest')).toBeInTheDocument()
})

test('quick actions shows View threat profile when the entity is resolved + View + Delete', () => {
  mockApi({})
  renderWithProviders(<InvestigationQuickActions investigation={INVESTIGATION} entity={ENTITY} />)
  expect(screen.getByRole('button', { name: 'View threat profile' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: /View documents & timeline/ })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Delete investigation' })).toBeEnabled()
})

test('quick actions offers no View threat profile while the target is unresolved', () => {
  mockApi({})
  renderWithProviders(<InvestigationQuickActions investigation={INVESTIGATION} entity={null} />)
  expect(screen.queryByRole('button', { name: 'View threat profile' })).not.toBeInTheDocument()
})

test('quick actions shows Resume + paused banner on a recovery-paused run', () => {
  mockApi({})
  const paused = { ...INVESTIGATION, state: 'paused', paused_reason: 'Server restart interrupted this run.' }
  renderWithProviders(<InvestigationQuickActions investigation={paused} entity={ENTITY} />)
  expect(screen.getByRole('status')).toHaveTextContent(/Server restart interrupted this run/)
  expect(screen.getByRole('button', { name: 'Resume investigation' })).toBeEnabled()
})

test('quick actions hides the paused banner when there is no reason (operator-paused)', () => {
  mockApi({})
  // paused_reason=null is the "operator pressed Stop" baseline — the operator knows what they
  // did, no banner needed.
  const paused = { ...INVESTIGATION, state: 'paused', paused_reason: null }
  renderWithProviders(<InvestigationQuickActions investigation={paused} entity={ENTITY} />)
  expect(screen.queryByRole('status')).not.toBeInTheDocument()
  // Resume still available either way.
  expect(screen.getByRole('button', { name: 'Resume investigation' })).toBeEnabled()
})

test('documents section lists the investigation documents and links to the standalone page', async () => {
  mockApi({
    'GET /api/investigations/12': {
      ...INVESTIGATION, stage_counts: {}, failures: [],
      documents: [{ id: 7, title: 'Report on Octo', publisher: 'ACME', stage: 'validated', published_at: null }],
    },
  })
  renderWithProviders(<DashboardDocuments investigationId="12" />)
  expect(await screen.findByRole('link', { name: 'Report on Octo' })).toHaveAttribute('href', '/documents/7')
  expect(screen.getByRole('link', { name: /View documents & timeline/ })).toHaveAttribute('href', '/investigations/12')
})
