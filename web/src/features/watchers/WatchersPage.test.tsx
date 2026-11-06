import { fireEvent, screen, waitFor } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { mockApi, renderWithProviders } from '../../test/utils'
import { WatchersPage } from './WatchersPage'

const WATCHER = {
  id: 1, target: 'APT29', entity_id: null, cron_expr: '0 8 * * *', enabled: true,
  created_by: 1, max_docs: 25, concurrency: 4, last_run_at: null,
  next_run_at: '2026-11-01T08:00:00', created_at: '2026-10-31T08:00:00', unseen_count: 2,
}

const CHANGES = [
  { id: 2, watcher_id: 1, target: 'APT29', entity_id: null, kind: 'new', subject: 'APT29',
    predicate: 'uses', object: 'OAuth token theft', from_status: null, to_status: 'single-source',
    citation: null, detected_at: '2026-10-31T10:00:00', run_job_id: null },
  { id: 1, watcher_id: 1, target: 'APT29', entity_id: null, kind: 'contested', subject: 'LockBit',
    predicate: 'attributed-to', object: 'Evil Corp', from_status: 'corroborated', to_status: 'contested',
    citation: null, detected_at: '2026-10-30T10:00:00', run_job_id: null },
]

function baseRoutes(extra: Record<string, unknown> = {}) {
  return { 'GET /api/watchers': [WATCHER], 'GET /api/watchers/changes': CHANGES, ...extra }
}

describe('WatchersPage', () => {
  it('a watcher is collapsed by default and expands to show its changes', async () => {
    mockApi(baseRoutes())
    renderWithProviders(<WatchersPage />)
    await waitFor(() => expect(screen.getByText('APT29')).toBeInTheDocument())
    // collapsed: the change feed is not shown until the watcher is opened
    expect(screen.queryByText('APT29 uses OAuth token theft')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { expanded: false }))
    await waitFor(() => expect(screen.getByText('APT29 uses OAuth token theft')).toBeInTheDocument())
    expect(screen.getByText('LockBit attributed-to Evil Corp')).toBeInTheDocument()
  })

  it("groups an expanded watcher's changes by day", async () => {
    mockApi(baseRoutes())  // the two changes are on 2026-10-31 and 2026-10-30
    renderWithProviders(<WatchersPage />)
    await waitFor(() => expect(screen.getByText('APT29')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { expanded: false }))
    await waitFor(() => expect(screen.getAllByTestId('day-group')).toHaveLength(2))
  })

  it("shows each watcher's cadence and run params", async () => {
    mockApi(baseRoutes())
    renderWithProviders(<WatchersPage />)
    await waitFor(() => expect(screen.getByText(/25 docs/)).toBeInTheDocument())
    expect(screen.getByText(/parallel 4/)).toBeInTheDocument()
  })

  it('a reader sees no manage controls', async () => {
    mockApi(baseRoutes({ 'GET /api/auth/me': { username: 'bob', role: 'reader' } }))
    renderWithProviders(<WatchersPage />)
    await waitFor(() => expect(screen.getByText('APT29')).toBeInTheDocument())
    expect(screen.queryByText('New watcher')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Pause' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Run now/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Delete watcher/ })).not.toBeInTheDocument()
  })

  it('an operator creates a watcher with cadence and run params', async () => {
    const fetchMock = mockApi(baseRoutes({
      'GET /api/auth/me': { username: 'op', role: 'operator' },
      'POST /api/watchers': { ...WATCHER, id: 9, target: 'LockBit' },
    }))
    renderWithProviders(<WatchersPage />)
    await waitFor(() => expect(screen.getByText('New watcher')).toBeInTheDocument())

    fireEvent.change(screen.getByPlaceholderText('e.g. APT29'), { target: { value: 'LockBit' } })
    fireEvent.change(screen.getByLabelText(/Max docs/i), { target: { value: '30' } })
    fireEvent.change(screen.getByLabelText(/Concurrency/i), { target: { value: '5' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create watcher' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/watchers', expect.objectContaining({ method: 'POST' }),
    ))
    const call = fetchMock.mock.calls.find(
      ([url, init]) => url === '/api/watchers' && (init as RequestInit)?.method === 'POST',
    )!
    const body = JSON.parse((call[1] as RequestInit).body as string)
    expect(body).toMatchObject({ target: 'LockBit', max_docs: 30, concurrency: 5 })
    expect(typeof body.cron_expr).toBe('string')
  })

  it('an operator can run now, pause and delete', async () => {
    const fetchMock = mockApi(baseRoutes({
      'GET /api/auth/me': { username: 'op', role: 'operator' },
      'PUT /api/watchers/1/enabled': { ...WATCHER, enabled: false },
      'DELETE /api/watchers/1': {},
      'POST /api/watchers/1/run-now': { job_id: 'j1' },
    }))
    renderWithProviders(<WatchersPage />)
    await waitFor(() => expect(screen.getByText('New watcher')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /Run now/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/watchers/1/run-now', expect.objectContaining({ method: 'POST' }),
    ))

    fireEvent.click(screen.getByRole('button', { name: 'Pause' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/watchers/1/enabled', expect.objectContaining({ method: 'PUT' }),
    ))

    fireEvent.click(screen.getByRole('button', { name: /Delete watcher/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/watchers/1', expect.objectContaining({ method: 'DELETE' }),
    ))
  })
})
