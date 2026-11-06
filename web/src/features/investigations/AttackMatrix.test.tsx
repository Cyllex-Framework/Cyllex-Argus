import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AttackMatrix } from './AttackMatrix'
import type { Tactic } from '../../api/types'
import { mockApi, renderWithProviders } from '../../test/utils'

const EMPTY_TACTICS: Tactic[] = [
  { id: 'reconnaissance', name: 'Reconnaissance', techniques: [] },
  { id: 'initial-access', name: 'Initial Access', techniques: [] },
  { id: 'execution', name: 'Execution', techniques: [] },
]

const WITH_TACTICS: Tactic[] = [
  { id: 'reconnaissance', name: 'Reconnaissance', techniques: [] },
  {
    id: 'initial-access', name: 'Initial Access',
    techniques: [
      { id: 'ap--1', external_id: 'T1566.004', name: 'Spearphishing Voice', status: 'corroborated', confidence: 40, admiralty: 'F2', sources: 3 },
      { id: 'ap--2', external_id: 'T1078', name: 'Valid Accounts', status: 'single-source', confidence: 30, admiralty: 'F3', sources: 1 },
    ],
  },
  {
    id: 'execution', name: 'Execution',
    techniques: [
      { id: 'ap--3', external_id: 'T1190', name: 'Exploit Public-Facing Application', status: 'contested', confidence: 20, admiralty: 'E3', sources: 2 },
    ],
  },
]

test('shows an empty message when no techniques are observed yet', () => {
  renderWithProviders(<AttackMatrix tactics={EMPTY_TACTICS} />)
  expect(screen.getByText(/No techniques observed yet/)).toBeInTheDocument()
})

test('renders only tactics that have techniques, in order', () => {
  renderWithProviders(<AttackMatrix tactics={WITH_TACTICS} />)
  const columns = screen.getAllByLabelText(/^(Reconnaissance|Initial Access|Execution)$/)
  expect(columns).toHaveLength(2)
  expect(columns[0]).toHaveAttribute('aria-label', 'Initial Access')
  expect(columns[1]).toHaveAttribute('aria-label', 'Execution')
})

test('each technique cell carries its status colour and the count badge', () => {
  renderWithProviders(<AttackMatrix tactics={WITH_TACTICS} />)
  const t1566 = screen.getByText('T1566.004').closest('button')!
  expect(t1566).toHaveClass('bg-emerald-700/60')
  const t1078 = screen.getByText('T1078').closest('button')!
  expect(t1078).toHaveClass('bg-amber-700/60')
  const t1190 = screen.getByText('T1190').closest('button')!
  expect(t1190).toHaveClass('bg-rose-700/60')
  const column = screen.getByLabelText('Initial Access')
  expect(column.querySelector('[data-testid="count-badge"]')).toHaveTextContent('2')
})

test('clicking a technique fires onSelect when provided (legacy mode)', async () => {
  const onSelect = vi.fn()
  renderWithProviders(<AttackMatrix tactics={WITH_TACTICS} onSelect={onSelect} />)
  await userEvent.click(screen.getByText('T1078').closest('button')!)
  expect(onSelect).toHaveBeenCalledWith('ap--2')
})

test('clicking a technique without onSelect opens the TechniqueModal', async () => {
  mockApi({ 'GET /api/threats/ap--2': { entity: { id: 'ap--2', name: 'Valid Accounts', stix_type: 'attack-pattern', external_id: 'T1078', attack: true, label: 'Valid Accounts (T1078)' }, aliases: [], facts: [] } })
  renderWithProviders(<AttackMatrix tactics={WITH_TACTICS} />)
  await userEvent.click(screen.getByText('T1078').closest('button')!)
  expect(await screen.findByRole('dialog')).toHaveAccessibleName(/^Technique /)
})

test('legend shows the three status colours', () => {
  renderWithProviders(<AttackMatrix tactics={WITH_TACTICS} />)
  const legend = screen.getByRole('list', { name: 'Legend' })
  expect(legend).toHaveTextContent('Corroborated')
  expect(legend).toHaveTextContent('Single source')
  expect(legend).toHaveTextContent('Contested')
})

test('the title no longer says Enterprise so the matrix also fits cloud or containers techniques', () => {
  renderWithProviders(<AttackMatrix tactics={WITH_TACTICS} />)
  expect(screen.getByRole('heading', { name: /ATT&CK techniques observed/i })).toBeInTheDocument()
  expect(screen.queryByText(/Enterprise/)).toBeNull()
})
