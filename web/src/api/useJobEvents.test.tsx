import { act, renderHook } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { STREAM_RETRY, useJobEvents } from './useJobEvents'
import { SESSION_EXPIRED_EVENT, TOKEN_STORAGE_KEY } from './client'
import { MockEventStream, mockApi } from '../test/utils'

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

const event = (seq: number, message = `step ${seq}`) => ({ seq, time: 't', message })
const refused = (status: number) => new Response(JSON.stringify({ error: 'unknown job' }), { status })

beforeEach(() => {
  MockEventStream.instances = []
  localStorage.clear()
  mockApi({})
})

test('collects events once each over a fetch stream that sends the token header, and stops at the end event', async () => {
  localStorage.setItem(TOKEN_STORAGE_KEY, 'tok-1')
  const { result } = renderHook(() => useJobEvents('job1'), { wrapper })
  const source = MockEventStream.instances[0]
  expect(source.url).toBe('/api/jobs/job1/events')
  expect(source.headers.get('X-Argus-Token')).toBe('tok-1')
  expect(source.headers.get('Accept')).toBe('text/event-stream')
  expect(source.init.credentials).toBe('omit')
  await act(async () => {
    await source.emit(event(1, 'Collected 3 candidate(s)'))
    await source.emit(event(2, 'Analyzing 1/2'))
    await source.emit(event(1, 'Collected 3 candidate(s)'))
  })
  expect(result.current.events.map((e) => e.seq)).toEqual([1, 2])
  // The end event alone (the server has not closed yet): the hook stops reading and cancels the stream.
  await act(() => source.send(`event: end\ndata: ${JSON.stringify({ id: 'job1', state: 'finished' })}\n\n`))
  expect(result.current.job?.state).toBe('finished')
  expect(result.current.ended).toBe(true)
  expect(result.current.lost).toBe(false)
  expect(source.closed).toBe(true)
  expect(MockEventStream.instances).toHaveLength(1)
})

test('parses events split across chunks and ignores keepalive comments', async () => {
  const { result } = renderHook(() => useJobEvents('job1'), { wrapper })
  const source = MockEventStream.instances[0]
  await act(async () => {
    await source.send(': keepalive\n\nid: 1\ndata: {"seq":1,"time":"t",')
    expect(result.current.events).toEqual([])
    await source.send('"message":"half"}\r\n\r\n: keepalive\n\nevent: e')
    await source.send('nd\ndata: {"id":"job1","state":"failed"}\n\n')
  })
  expect(result.current.events).toEqual([{ seq: 1, time: 't', message: 'half' }])
  expect(result.current.job?.state).toBe('failed')
})

test('a null end payload still marks the stream ended, with no job', async () => {
  const { result } = renderHook(() => useJobEvents('gone'), { wrapper })
  expect(result.current.ended).toBe(false)
  await act(() => MockEventStream.instances[0].emitEnd(null))
  expect(result.current.ended).toBe(true)
  expect(result.current.job).toBeNull()
  expect(result.current.lost).toBe(false)
})

test('ended is true with the final job after a normal end, and resets when the job id changes', async () => {
  const { result, rerender } = renderHook(({ id }) => useJobEvents(id), { wrapper, initialProps: { id: 'a' } })
  await act(() => MockEventStream.instances[0].emitEnd({ id: 'a', state: 'finished' }))
  expect(result.current.ended).toBe(true)
  expect(result.current.job?.state).toBe('finished')
  rerender({ id: 'b' })
  expect(result.current.ended).toBe(false)
  expect(result.current.job).toBeNull()
  expect(MockEventStream.instances[1].url).toBe('/api/jobs/b/events')
})

test('a job id change or unmount aborts the running stream', async () => {
  const { rerender, unmount } = renderHook(({ id }) => useJobEvents(id), { wrapper, initialProps: { id: 'a' } })
  const first = MockEventStream.instances[0]
  rerender({ id: 'b' })
  expect(first.aborted).toBe(true)
  const second = MockEventStream.instances[1]
  unmount()
  expect(second.aborted).toBe(true)
  await act(() => second.emit(event(1))) // nothing to deliver to, and nothing throws
})

test('no job id means no stream', () => {
  const { result } = renderHook(() => useJobEvents(null), { wrapper })
  expect(MockEventStream.instances).toHaveLength(0)
  expect(result.current.events).toEqual([])
})

test('a dropped connection reconnects after the last seen event and keeps going', async () => {
  const { result } = renderHook(() => useJobEvents('job1'), { wrapper })
  await act(async () => {
    await MockEventStream.instances[0].emit(event(1))
    await MockEventStream.instances[0].emit(event(2))
    await MockEventStream.instances[0].fail()
  })
  expect(result.current.ended).toBe(false)
  expect(MockEventStream.instances.map((s) => s.url)).toEqual(['/api/jobs/job1/events', '/api/jobs/job1/events?after=2'])
  await act(async () => {
    await MockEventStream.instances[1].close() // the body ending without the end event is a drop too
  })
  expect(MockEventStream.instances[2].url).toBe('/api/jobs/job1/events?after=2')
  await act(async () => {
    await MockEventStream.instances[2].emit(event(3))
    await MockEventStream.instances[2].emitEnd({ id: 'job1', state: 'finished' })
  })
  expect(result.current.events.map((e) => e.seq)).toEqual([1, 2, 3])
  expect(result.current.job?.state).toBe('finished')
  expect(result.current.lost).toBe(false)
})

test('a stream that keeps dropping without progress is given up as lost', async () => {
  const { result } = renderHook(() => useJobEvents('job1'), { wrapper })
  await act(() => MockEventStream.instances[0].emit(event(1)))
  for (let attempt = 0; attempt <= STREAM_RETRY.attempts; attempt++) {
    expect(result.current.ended).toBe(false)
    await act(() => MockEventStream.instances[attempt].fail())
  }
  expect(MockEventStream.instances).toHaveLength(STREAM_RETRY.attempts + 1)
  expect(result.current.ended).toBe(true)
  expect(result.current.lost).toBe(true)
  expect(result.current.job).toBeNull()
  expect(result.current.events.map((e) => e.seq)).toEqual([1])
})

test('a refused stream (e.g. a 404 after a server restart) ends as lost at once instead of running forever', async () => {
  let calls = 0
  mockApi({ 'GET /api/jobs/job1/events': (init: RequestInit, url: string) => (calls++ ? refused(404) : new MockEventStream(url, init)) })
  const { result } = renderHook(() => useJobEvents('job1'), { wrapper })
  await act(() => MockEventStream.instances[0].emit(event(1)))
  await act(() => MockEventStream.instances[0].fail())
  expect(calls).toBe(2)
  expect(result.current.ended).toBe(true)
  expect(result.current.lost).toBe(true)
  expect(result.current.job).toBeNull()
  expect(result.current.events.map((e) => e.seq)).toEqual([1])
})

test('a 401 marks the stream lost and reports the expired session', async () => {
  mockApi({ 'GET /api/jobs/job1/events': refused(401) })
  const listener = vi.fn()
  window.addEventListener(SESSION_EXPIRED_EVENT, listener)
  const { result } = renderHook(() => useJobEvents('job1'), { wrapper })
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)))
  expect(result.current.lost).toBe(true)
  expect(listener).toHaveBeenCalledTimes(1)
  window.removeEventListener(SESSION_EXPIRED_EVENT, listener)
})

test('a malformed event is skipped without breaking the stream', async () => {
  const { result } = renderHook(() => useJobEvents('job1'), { wrapper })
  await act(async () => {
    await MockEventStream.instances[0].send('data: {not json\n\n')
    await MockEventStream.instances[0].emit(event(1))
  })
  expect(result.current.events.map((e) => e.seq)).toEqual([1])
  expect(MockEventStream.instances).toHaveLength(1)
})
