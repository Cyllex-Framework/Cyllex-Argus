import { act, renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { jobPage, pickJob, useAttackCatalog, useJobs, useRefreshWhenJobsEnd } from './hooks'
import type { Job } from './types'
import { mockApi } from '../test/utils'

const job = (id: string, kind: Job['kind'], state: Job['state'], params: Record<string, unknown> = {}): Job => ({
  id, kind, params, state, created_at: 't', started_at: null, finished_at: null, message: null, result: null, events: 0,
})

describe('pickJob', () => {
  // The server lists jobs newest first.
  const jobs = [
    job('q2', 'investigate', 'queued'),
    job('q1', 'investigate', 'queued'),
    job('r1', 'investigate', 'running'),
    job('i1', 'ingest', 'finished'),
    job('f1', 'investigate', 'finished'),
  ]

  test('prefers the running job of the kinds, then the oldest queued one', () => {
    expect(pickJob(jobs, ['investigate'])).toBe('r1')
    expect(pickJob(jobs.filter((j) => j.id !== 'r1'), ['investigate'])).toBe('q1')
  })

  test('a job this page just started wins while it is active, and before the list knows it', () => {
    expect(pickJob(jobs, ['investigate'], { started: 'q2' })).toBe('q2')
    expect(pickJob(jobs, ['investigate'], { started: 'new' })).toBe('new')
    expect(pickJob(undefined, ['investigate'], { started: 'new' })).toBe('new')
  })

  test('once the started job is over, an active job of the kinds takes over, else the started job stays', () => {
    const done = [job('s1', 'investigate', 'finished'), job('r1', 'investigate', 'running')]
    expect(pickJob(done, ['investigate'], { started: 's1' })).toBe('r1')
    expect(pickJob([job('s1', 'investigate', 'finished'), job('f0', 'investigate', 'finished')], ['investigate'], { started: 's1' })).toBe('s1')
  })

  test('with nothing active, the most recent job of the kinds, unless the caller only wants active jobs', () => {
    const idle = [job('a1', 'attack_update', 'failed'), job('i1', 'ingest', 'finished'), job('i0', 'ingest', 'finished')]
    expect(pickJob(idle, ['ingest'])).toBe('i1')
    expect(pickJob(idle, ['ingest'], { latest: false })).toBeNull()
    expect(pickJob(idle, ['investigate'])).toBeNull()
    expect(pickJob(undefined, ['ingest'])).toBeNull()
  })

  test('a matcher narrows the jobs further', () => {
    const resumes = [job('r4', 'resume', 'running', { investigation_id: 4 }), job('r3', 'resume', 'finished', { investigation_id: 3 })]
    expect(pickJob(resumes, ['resume'], { matches: (j) => j.params.investigation_id === 3 })).toBe('r3')
  })
})

test('jobPage sends each kind of job to the page that shows its progress', () => {
  expect(jobPage(job('j', 'investigate', 'running', { target: 'x' }))).toBe('/investigations')
  expect(jobPage(job('j', 'investigate', 'running', { target: 'x', investigation_id: 7 }))).toBe('/investigations/7/dashboard')
  expect(jobPage(job('j', 'resume', 'running', { investigation_id: 7 }))).toBe('/investigations/7/dashboard')
  expect(jobPage(job('j', 'ingest', 'running'))).toBe('/documents')
  expect(jobPage(job('j', 'attack_update', 'running'))).toBe('/settings')
  expect(jobPage(job('j', 'recompute', 'running'))).toBe('/sources')
})

test('useRefreshWhenJobsEnd refreshes every query when an active job ends, and only then', async () => {
  let list = [job('j1', 'investigate', 'running')]
  mockApi({ 'GET /api/jobs': () => list, 'GET /api/overview': {} })
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>
  const { result } = renderHook(() => { useRefreshWhenJobsEnd(); return useJobs() }, { wrapper })
  await waitFor(() => expect(result.current.data?.[0].state).toBe('running'))
  const invalidate = vi.spyOn(client, 'invalidateQueries')
  await act(() => client.refetchQueries({ queryKey: ['jobs'] }))
  expect(invalidate).not.toHaveBeenCalled() // still running
  list = [job('j1', 'investigate', 'finished')]
  await act(() => client.refetchQueries({ queryKey: ['jobs'] }))
  await waitFor(() => expect(invalidate).toHaveBeenCalledWith())
})

describe('useAttackCatalog', () => {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
  )

  test('loads the catalog from /api/attack/catalog', async () => {
    const catalog = { tactics: [{ id: 'execution', name: 'Execution', techniques: [] }] }
    const fetchMock = mockApi({ 'GET /api/attack/catalog': catalog })
    const { result } = renderHook(() => useAttackCatalog(), { wrapper })
    await waitFor(() => expect(result.current.data).toEqual(catalog))
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  test('a 404 (ATT&CK not loaded) is an error, not retried', async () => {
    mockApi({ 'GET /api/attack/catalog': () => new Response(JSON.stringify({ error: 'ATT&CK data not loaded' }), { status: 404 }) })
    const { result } = renderHook(() => useAttackCatalog(), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
  })
})
