import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { EntityDetailPanel } from './EntityDetailPanel'
import { mockApi, renderWithProviders } from '../../test/utils'

const PROFILE = {
  entity: { id: 'ap--1', stix_type: 'attack-pattern', name: 'Spearphishing Voice', external_id: 'T1566.004', attack: true, label: 'Spearphishing Voice (T1566.004)' },
  aliases: [{ alias: 'Vishing', origin: 'document' }],
  facts: [{
    subject: { id: 'is--1', stix_type: 'intrusion-set', name: 'Scattered Spider', external_id: null, attack: true, label: 'Scattered Spider' },
    predicate: 'uses',
    object: { id: 'ap--1', stix_type: 'attack-pattern', name: 'Spearphishing Voice', external_id: 'T1566.004', attack: true, label: 'Spearphishing Voice (T1566.004)' },
    status: 'corroborated', confidence: 60, admiralty: 'B2', first_seen: null, last_seen: null, source_count: 2,
    citations: [{ claim_id: 1, quote: 'They phoned the help desk', quote_status: 'verified', polarity: 'asserts', document_title: 'Report', location: 'https://example.com/r', publisher: 'ACME', published_at: null }],
  }],
}

test('renders nothing and fetches nothing when entityId is null', () => {
  const fetchMock = mockApi({})
  renderWithProviders(<EntityDetailPanel entityId={null} onClose={vi.fn()} />)
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(fetchMock).not.toHaveBeenCalled()
})

test('opens for an entity and renders its name, type, aliases, facts and the focused close button', async () => {
  mockApi({ 'GET /api/threats/ap--1': PROFILE })
  renderWithProviders(<EntityDetailPanel entityId="ap--1" onClose={vi.fn()} />)
  const dialog = screen.getByRole('dialog')
  expect(dialog).toHaveClass('fixed', 'inset-y-0', 'right-0', 'w-[480px]')
  expect(screen.getByRole('button', { name: 'Close' })).toHaveFocus()
  expect(await screen.findByRole('heading', { name: 'Spearphishing Voice' })).toBeInTheDocument()
  expect(screen.getByText(/attack-pattern/)).toBeInTheDocument()
  expect(screen.getByText('Vishing')).toBeInTheDocument()
  expect(screen.getByRole('cell', { name: 'Scattered Spider' })).toBeInTheDocument()
})

test('selecting a fact shows its citations', async () => {
  mockApi({ 'GET /api/threats/ap--1': PROFILE })
  renderWithProviders(<EntityDetailPanel entityId="ap--1" onClose={vi.fn()} />)
  await userEvent.click(await screen.findByRole('cell', { name: 'Scattered Spider' }))
  expect(screen.getByText(/They phoned the help desk/)).toBeInTheDocument()
})

test('Escape and a backdrop click fire onClose; a click inside the panel does not', async () => {
  mockApi({ 'GET /api/threats/ap--1': PROFILE })
  const onClose = vi.fn()
  renderWithProviders(<EntityDetailPanel entityId="ap--1" onClose={onClose} />)
  await screen.findByRole('heading', { name: 'Spearphishing Voice' })
  await userEvent.click(screen.getByRole('dialog'))
  expect(onClose).not.toHaveBeenCalled()
  await userEvent.keyboard('{Escape}')
  expect(onClose).toHaveBeenCalledTimes(1)
  await userEvent.click(screen.getByTestId('entity-panel-backdrop'))
  expect(onClose).toHaveBeenCalledTimes(2)
})

test('a technique id links to attack.mitre.org safely', async () => {
  mockApi({ 'GET /api/threats/ap--1': PROFILE })
  renderWithProviders(<EntityDetailPanel entityId="ap--1" onClose={vi.fn()} />)
  const link = await screen.findByRole('link', { name: /attack\.mitre\.org/ })
  expect(link).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1566/004/')
  expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  expect(link).toHaveAttribute('target', '_blank')
})

test('a non-technique external id has no ATT&CK link', async () => {
  const profile = { ...PROFILE, entity: { ...PROFILE.entity, stix_type: 'intrusion-set', external_id: 'G1015' } }
  mockApi({ 'GET /api/threats/ap--1': profile })
  renderWithProviders(<EntityDetailPanel entityId="ap--1" onClose={vi.fn()} />)
  await screen.findByRole('heading', { name: 'Spearphishing Voice' })
  expect(screen.queryByRole('link', { name: /attack\.mitre\.org/ })).not.toBeInTheDocument()
})

test('an unknown entity shows a not-found state with a Close button', async () => {
  mockApi({ 'GET /api/threats/nope': new Response(JSON.stringify({ error: 'unknown threat' }), { status: 404 }) })
  const onClose = vi.fn()
  renderWithProviders(<EntityDetailPanel entityId="nope" onClose={onClose} />)
  expect(await screen.findByText(/not found/i)).toBeInTheDocument()
  const buttons = screen.getAllByRole('button', { name: 'Close' })
  await userEvent.click(buttons[buttons.length - 1])
  expect(onClose).toHaveBeenCalled()
})

function withDetail(stix_type: string, detail?: unknown) {
  return { ...PROFILE, entity: { ...PROFILE.entity, stix_type, external_id: null, attack: false }, ...(detail ? { detail } : {}) }
}

test('an indicator shows value, kind and a freshness pill with the last-seen date', async () => {
  mockApi({ 'GET /api/threats/ap--1': withDetail('indicator', { kind: 'domain', value: 'evil.example', freshness: 'active', last_seen: '2026-09-01' }) })
  renderWithProviders(<EntityDetailPanel entityId="ap--1" onClose={vi.fn()} />)
  expect(await screen.findByText('evil.example', { selector: 'code' })).toBeInTheDocument()
  expect(screen.getByText(/Kind: domain/)).toBeInTheDocument()
  expect(screen.getByText('active')).toBeInTheDocument()
  expect(screen.getByText(/last seen 2026-09-01/)).toBeInTheDocument()
})

test('an indicator with unknown freshness says there is no dated citation', async () => {
  mockApi({ 'GET /api/threats/ap--1': withDetail('indicator', { kind: 'ip', value: '203.0.113.9', freshness: 'unknown', last_seen: null }) })
  renderWithProviders(<EntityDetailPanel entityId="ap--1" onClose={vi.fn()} />)
  expect(await screen.findByText(/no dated citation/)).toBeInTheDocument()
  expect(screen.queryByText(/last seen/)).not.toBeInTheDocument()
})

test('an identity shows its sector hint, and nothing when there is none', async () => {
  mockApi({ 'GET /api/threats/ap--1': withDetail('identity', { sector_hint: 'Finance' }) })
  const { unmount } = renderWithProviders(<EntityDetailPanel entityId="ap--1" onClose={vi.fn()} />)
  expect(await screen.findByText(/Sector: Finance/)).toBeInTheDocument()
  unmount()
  mockApi({ 'GET /api/threats/ap--1': withDetail('identity') })
  renderWithProviders(<EntityDetailPanel entityId="ap--1" onClose={vi.fn()} />)
  await screen.findByRole('heading', { name: 'Spearphishing Voice' })
  expect(screen.queryByText(/Sector/)).not.toBeInTheDocument()
})

test('a vulnerability shows its CVE with a safe NVD link', async () => {
  mockApi({ 'GET /api/threats/ap--1': withDetail('vulnerability', { cve_id: 'CVE-2024-3400' }) })
  renderWithProviders(<EntityDetailPanel entityId="ap--1" onClose={vi.fn()} />)
  const link = await screen.findByRole('link', { name: /NVD/ })
  expect(link).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2024-3400')
  expect(link).toHaveAttribute('target', '_blank')
  expect(link).toHaveAttribute('rel', 'noopener noreferrer')
})
