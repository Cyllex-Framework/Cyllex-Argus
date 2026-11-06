import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DashboardPage } from './DashboardPage'
import { mockApi, renderWithProviders } from '../../test/utils'

const OVERVIEW = {
  counts: {
    threats: 8,
    documents: { validated: 42 },
    assessments: { corroborated: 19, contested: 2 },
    investigations: 5,
  },
  recent_investigations: [
    { id: 3, target: 'Scattered Spider', state: 'finished', started_at: '2026-10-20T10:00:00Z', stage_counts: { validated: 4 } },
  ],
  unrated_publishers: [{ id: 1, name: 'Mandiant' }],
}

/** A store that has been used — the shape that made the landing page unreadable. */
const BUSY_HEALTH = {
  totals: {
    failed_documents: 15, untagged_identities: 71, unrated_publishers: 38,
    stuck_investigations: 1, likely_mistyped_identities: 0, name_collisions: 8,
  },
  failed_documents: [{
    id: 1, title: 'Hewlett Packard Enterprise Co - Form 8-K', publisher: 'SEC',
    failure_reason: 'HTTP 403 for https://www.sec.gov/Archives/edgar/data/1045810/hpe-20240119.htm',
  }],
  untagged_identities: [{ id: 'identity--1', name: 'AT&T' }, { id: 'identity--2', name: 'Caesars Palace' }],
  unrated_publishers: [{ id: 1, name: 'Australian Cyber Security Centre (ACSC)' }],
  stuck_investigations: [{ id: 9, target: 'APT29 Microsoft', state: 'running', started_at: '2026-10-25T08:00:00Z' }],
  likely_mistyped_identities: [],
  name_collisions: [{
    name: 'Akira',
    entities: [
      { id: 'intrusion-set--1', stix_type: 'intrusion-set', external_id: 'G1024' },
      { id: 'malware--1', stix_type: 'malware', external_id: 'S1129' },
    ],
  }],
}

const CLEAN_HEALTH = {
  totals: {
    failed_documents: 0, untagged_identities: 0, unrated_publishers: 0,
    stuck_investigations: 0, likely_mistyped_identities: 0, name_collisions: 0,
  },
  failed_documents: [], untagged_identities: [], unrated_publishers: [],
  stuck_investigations: [], likely_mistyped_identities: [], name_collisions: [],
}

const routes = (health: unknown) => ({
  'GET /api/overview': OVERVIEW,
  'GET /api/health': health,
  'GET /api/settings': { attack: { present: true }, claude: { found: true }, config: {}, home: 'C:/argus' },
  'GET /api/jobs': [],
})

/** The disclosure is what the operator sees collapsed or expanded; `<details>` keeps its
 *  children in the DOM either way, so `open` — not presence — is the thing to assert. */
const disclosure = (container: HTMLElement) => container.querySelector('details') as HTMLDetailsElement | null

test('data health opens as one line of counts, not as a page of lists', async () => {
  mockApi(routes(BUSY_HEALTH))
  const { container } = renderWithProviders(<DashboardPage />)
  // The card renders its title while the health query is still in flight, so wait for the
  // disclosure itself rather than for the heading.
  await waitFor(() => expect(disclosure(container)).not.toBeNull())

  const details = disclosure(container)!
  expect(details.open).toBe(false)

  // The counts answer "is there anything to do?" without opening anything.
  const summary = details.querySelector('summary')!
  expect(summary.textContent).toMatch(/15 failed documents/)
  expect(summary.textContent).toMatch(/71 untagged identities/)
  expect(summary.textContent).toMatch(/38 unrated publishers/)
  expect(summary.textContent).toMatch(/1 stuck run\b/)
  expect(summary.textContent).toMatch(/8 name collisions/)
  // The lists and the red failure URLs live behind it, not on the summary line.
  expect(summary.textContent).not.toMatch(/Hewlett Packard/)
  expect(summary.textContent).not.toMatch(/HTTP 403/)
})

test('the detail is one click away when the operator does come to clean up', async () => {
  mockApi(routes(BUSY_HEALTH))
  const { container } = renderWithProviders(<DashboardPage />)
  await userEvent.click(await screen.findByText(/Show details/))

  expect(disclosure(container)!.open).toBe(true)
  expect(screen.getByRole('link', { name: 'Hewlett Packard Enterprise Co - Form 8-K' })).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'AT&T' })).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Australian Cyber Security Centre (ACSC)' })).toBeInTheDocument()
})

test('a clean store says so in one green line, with nothing to expand', async () => {
  mockApi(routes(CLEAN_HEALTH))
  const { container } = renderWithProviders(<DashboardPage />)

  expect(await screen.findByText(/Nothing to clean up/)).toBeInTheDocument()
  expect(disclosure(container)).toBeNull()
})

test('the knowledge base comes before the housekeeping', async () => {
  mockApi(routes(BUSY_HEALTH))
  const { container } = renderWithProviders(<DashboardPage />)
  await screen.findByText('Recent investigations')

  const text = container.textContent ?? ''
  expect(text).toContain('Threats with facts')
  expect(text.indexOf('Threats with facts')).toBeLessThan(text.indexOf('Data health'))
})

test('the counts and the recent work still render', async () => {
  mockApi(routes(CLEAN_HEALTH))
  renderWithProviders(<DashboardPage />)

  expect(await screen.findByText('Threats with facts')).toBeInTheDocument()
  const recent = screen.getByText('Recent investigations').closest('section')!
  await waitFor(() => expect(within(recent).getByRole('link', { name: 'Scattered Spider' })).toBeInTheDocument())
})
