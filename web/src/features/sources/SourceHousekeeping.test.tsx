import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SourcesPage } from './SourcesPage'
import { mockApi, renderWithProviders } from '../../test/utils'

/**
 * The two bulk publisher actions, which were CLI-only — which is to say unreachable, since this
 * tool is used in the browser. What these tests hold is the honesty of the offer: the reasoning
 * is on screen, the direction confidence will move is stated, and a grade a human set is never
 * quietly undone.
 */

const SOURCES = [
  { id: 1, name: 'CISA', domain: 'cisa.gov', reliability: 'F', documents: 5, tlp: null, also_known_as: [] },
  { id: 2, name: 'US-CERT', domain: null, reliability: 'F', documents: 1, tlp: null, also_known_as: [] },
]

const GRADEABLE = {
  proposals: [
    {
      id: 1, name: 'CISA', current: 'F', proposed: 'A', organisation: 'cisa.gov',
      rationale: 'US cyber defence agency; joint advisories with primary incident access',
      overrides_analyst: false,
    },
  ],
  would_override: [],
  unjudged: 2,
  unrecognised: 1,
  publishers: 2,
}

const DUPLICATES = {
  groups: [{
    org_key: 'cisa.gov',
    keep: { id: 1, name: 'CISA', documents: 5 },
    drop: [{ id: 2, name: 'US-CERT', documents: 1 }],
  }],
  rows: 2,
}

const EMPTY_GRADEABLE = { proposals: [], would_override: [], unjudged: 0, unrecognised: 0, publishers: 2 }
const EMPTY_DUPLICATES = { groups: [], rows: 0 }

const routes = (overrides: Record<string, unknown> = {}) => ({
  'GET /api/sources': SOURCES,
  'GET /api/sources/gradeable': GRADEABLE,
  'GET /api/sources/duplicates': DUPLICATES,
  'GET /api/jobs': [],
  ...overrides,
})

// -- grading ---------------------------------------------------------------------------------

test('the grading offer says why F is not a neutral default, and what will move', async () => {
  mockApi(routes())
  renderWithProviders(<SourcesPage />)

  const heading = await screen.findByText(/1 of your 2 publishers/)
  const card = heading.closest('section, div')!
  // The reason an operator should care: F is the floor the evidence is multiplied by.
  expect(card.textContent).toMatch(/floor/)
  expect(card.textContent).toMatch(/reliability cannot be judged/)
  // And the direction the numbers will move, before they move.
  expect(card.textContent).toMatch(/confidence to go/)
  // Plus what is NOT covered, so the card never implies the job is finished.
  expect(card.textContent).toMatch(/1 other stay(s)? at F/)
})

test('the per-publisher reasoning is one click away, not hidden and not in the way', async () => {
  const { container } = mockApi(routes()) && renderWithProviders(<SourcesPage />)
  await screen.findByText(/1 of your 2 publishers/)

  const details = container.querySelector('details') as HTMLDetailsElement
  expect(details.open).toBe(false)
  await userEvent.click(screen.getByText(/Review the 1 proposed grades/))
  expect(details.open).toBe(true)
  // The rationale is the thing being reviewed: the operator is accepting a judgement.
  expect(screen.getByText(/joint advisories with primary incident access/)).toBeInTheDocument()
})

test('grading posts once and follows the rescore it queued', async () => {
  const calls: string[] = []
  const fetchMock = mockApi(routes({
    'POST /api/sources/rate-known': () => {
      calls.push('rate-known')
      return { graded: 1, job: { id: 'job-1', kind: 'recompute', state: 'running' } }
    },
  }))
  renderWithProviders(<SourcesPage />)

  await userEvent.click(await screen.findByRole('button', { name: 'Grade 1 publisher' }))

  await waitFor(() => expect(calls).toEqual(['rate-known']))
  expect(await screen.findByRole('status')).toHaveTextContent(/Graded 1 publisher/)
  expect(fetchMock).toHaveBeenCalled()
})

test('a store with the axis already in use is told nothing', async () => {
  mockApi(routes({ 'GET /api/sources/gradeable': EMPTY_GRADEABLE, 'GET /api/sources/duplicates': EMPTY_DUPLICATES }))
  renderWithProviders(<SourcesPage />)

  // The table still renders; the exhortations do not. A page that always nags trains the eye
  // to skip it.
  expect(await screen.findByRole('cell', { name: 'CISA' })).toBeInTheDocument()
  expect(screen.queryByText(/publishers are sources Argus/)).not.toBeInTheDocument()
  expect(screen.queryByText(/One organisation, several rows/)).not.toBeInTheDocument()
})

test('publishers nobody can grade are named as such, not as a pending task', async () => {
  mockApi(routes({
    'GET /api/sources/gradeable': { ...EMPTY_GRADEABLE, unjudged: 2, unrecognised: 2 },
  }))
  renderWithProviders(<SourcesPage />)

  const note = await screen.findByText(/2 publishers still unjudged/)
  expect(note.textContent).toMatch(/no basis to grade/)
})

// -- merging ---------------------------------------------------------------------------------

test('the merge offer states that confidence will drop, and that nothing is lost', async () => {
  mockApi(routes())
  renderWithProviders(<SourcesPage />)

  const heading = await screen.findByText(/2 publisher rows are 1 organisation/)
  const card = heading.closest('section, div')!
  expect(card.textContent).toMatch(/corroboration is counted per publisher row/i)
  expect(card.textContent).toMatch(/confidence to go/)
  expect(card.textContent).toMatch(/every byline\s+is kept|every byline is kept/)
  // The rows themselves, so the operator can check the grouping before accepting it.
  expect(screen.getByText(/\+ US-CERT/)).toBeInTheDocument()
})

test('a single organisation can be merged on its own', async () => {
  const bodies: unknown[] = []
  mockApi(routes({
    'POST /api/sources/merge-duplicates': (init: RequestInit) => {
      bodies.push(JSON.parse(String(init.body)))
      return { groups: 1, rows_merged: 1, documents_moved: 1, job: { id: 'job-2', kind: 'recompute', state: 'running' } }
    },
  }))
  renderWithProviders(<SourcesPage />)

  await userEvent.click(await screen.findByRole('button', { name: 'Merge' }))

  // Scoped to the group the operator chose, not the whole scan.
  await waitFor(() => expect(bodies).toEqual([{ org_keys: ['cisa.gov'] }]))
})

test('a merged row shows the bylines it now speaks for', async () => {
  mockApi(routes({
    'GET /api/sources': [{ ...SOURCES[0], also_known_as: ['US-CERT', 'CISA Advisory'] }],
    'GET /api/sources/duplicates': EMPTY_DUPLICATES,
  }))
  renderWithProviders(<SourcesPage />)

  // The row is the unit of independence, so whose reporting it covers is what is being rated.
  expect(await screen.findByText(/also: US-CERT, CISA Advisory/)).toBeInTheDocument()
})
