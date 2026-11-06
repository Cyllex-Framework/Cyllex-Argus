import { fireEvent, screen, waitFor } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { mockApi, renderWithProviders } from '../test/utils'
import { WatchersMenu, relativeFromNow } from './WatchersMenu'

const WATCHERS = [
  {
    id: 1, target: 'APT29', entity_id: null, cron_expr: '0 8 * * *', enabled: true, created_by: 1,
    max_docs: 25, concurrency: 4, last_run_at: null,
    next_run_at: new Date(Date.now() + 3 * 3600 * 1000).toISOString(),
    created_at: '2026-11-01T08:00:00', unseen_count: 2,
  },
  {
    id: 2, target: 'LockBit', entity_id: null, cron_expr: '0 8 * * *', enabled: false, created_by: 1,
    max_docs: null, concurrency: 1,
    last_run_at: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
    next_run_at: '2026-11-02T08:00:00', created_at: '2026-11-01T08:00:00', unseen_count: 0,
  },
]

const RUNNING_JOB = {
  id: 'j1', kind: 'investigate', params: { watcher_id: 1, target: 'APT29' }, state: 'running',
  created_at: '', started_at: '', finished_at: null, message: null, result: null, events: 0,
}

describe('relativeFromNow', () => {
  it('formats future and past and null', () => {
    const now = Date.now()
    expect(relativeFromNow(new Date(now + 3 * 3600 * 1000).toISOString(), now)).toBe('in 3h')
    expect(relativeFromNow(new Date(now - 2 * 3600 * 1000).toISOString(), now)).toBe('2h ago')
    expect(relativeFromNow(new Date(now + 2 * 86400 * 1000).toISOString(), now)).toBe('in 2d')
    expect(relativeFromNow(null)).toBe('—')
  })
})

describe('WatchersMenu', () => {
  it('shows the unseen total and lists watchers with next-run / paused state', async () => {
    mockApi({ 'GET /api/watchers': WATCHERS, 'GET /api/jobs': [] })
    renderWithProviders(<WatchersMenu />)
    await waitFor(() => expect(screen.getByTestId('watchers-unseen')).toHaveTextContent('2'))

    fireEvent.click(screen.getByRole('button', { name: 'Watchers' }))
    expect(screen.getByText('APT29')).toBeInTheDocument()
    expect(screen.getByText(/next run in 3h/)).toBeInTheDocument()
    expect(screen.getByText(/paused/)).toBeInTheDocument()       // LockBit is disabled
    expect(screen.getByText(/last ran 2h ago/)).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: /Open Watchers/ })).toBeInTheDocument()
  })

  it('renders an empty state with no watchers', async () => {
    mockApi({ 'GET /api/watchers': [], 'GET /api/jobs': [] })
    renderWithProviders(<WatchersMenu />)
    fireEvent.click(await screen.findByRole('button', { name: 'Watchers' }))
    expect(screen.getByText(/No watchers yet/)).toBeInTheDocument()
  })

  it('marks a watcher as running when it has an active investigate job', async () => {
    mockApi({ 'GET /api/watchers': WATCHERS, 'GET /api/jobs': [RUNNING_JOB] })
    renderWithProviders(<WatchersMenu />)
    await waitFor(() => expect(screen.getByTestId('watchers-running')).toHaveTextContent('1'))

    fireEvent.click(screen.getByRole('button', { name: 'Watchers' }))
    expect(screen.getByText(/running now/)).toBeInTheDocument()
  })
})
