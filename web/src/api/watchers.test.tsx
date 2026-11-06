import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactElement } from 'react'
import { describe, it, expect } from 'vitest'
import { mockApi } from '../test/utils'
import { useMarkWatcherSeen, useWatcherMutations, useWatchers } from './hooks'

function wrap(ui: ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>)
}

function List() {
  const { data } = useWatchers()
  return <ul>{(data ?? []).map((w) => <li key={w.id}>{`${w.target}:${w.unseen_count}`}</li>)}</ul>
}

function Buttons() {
  const { create, setEnabled, remove } = useWatcherMutations()
  const seen = useMarkWatcherSeen()
  return (
    <>
      <button onClick={() => create.mutate({ target: 'LockBit' })}>create</button>
      <button onClick={() => setEnabled.mutate({ id: 1, enabled: false })}>disable</button>
      <button onClick={() => remove.mutate(1)}>remove</button>
      <button onClick={() => seen.mutate({ id: 1, last_change_id: 9 })}>seen</button>
    </>
  )
}

describe('watcher hooks', () => {
  it('useWatchers fetches and parses rows', async () => {
    mockApi({ 'GET /api/watchers': [{ id: 1, target: 'APT29', unseen_count: 3, enabled: true }] })
    wrap(<List />)
    await waitFor(() => expect(screen.getByText('APT29:3')).toBeInTheDocument())
  })

  it('mutations hit the right endpoints', async () => {
    const fetchMock = mockApi({
      'POST /api/watchers': { id: 2, target: 'LockBit', unseen_count: 0 },
      'PUT /api/watchers/1/enabled': { id: 1, target: 'APT29', unseen_count: 0 },
      'DELETE /api/watchers/1': {},
      'POST /api/watchers/1/seen': {},
    })
    wrap(<Buttons />)

    fireEvent.click(screen.getByText('create'))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/watchers', expect.objectContaining({ method: 'POST', body: JSON.stringify({ target: 'LockBit' }) }),
    ))
    fireEvent.click(screen.getByText('disable'))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/watchers/1/enabled', expect.objectContaining({ method: 'PUT', body: JSON.stringify({ enabled: false }) }),
    ))
    fireEvent.click(screen.getByText('remove'))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/watchers/1', expect.objectContaining({ method: 'DELETE' }),
    ))
    fireEvent.click(screen.getByText('seen'))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/watchers/1/seen', expect.objectContaining({ method: 'POST', body: JSON.stringify({ last_change_id: 9 }) }),
    ))
  })
})
