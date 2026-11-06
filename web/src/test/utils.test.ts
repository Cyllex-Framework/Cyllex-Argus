import { MockEventStream, mockApi } from './utils'

test('mockApi lets a route that returns a Response be fetched more than once', async () => {
  mockApi({ 'GET /api/thing': new Response(JSON.stringify({ ok: true }), { status: 200 }) })
  const first = await fetch('/api/thing')
  const second = await fetch('/api/thing')
  expect(await first.json()).toEqual({ ok: true })
  expect(await second.json()).toEqual({ ok: true })
})

test('mockApi serves an unrouted job event stream as a streamed response', async () => {
  MockEventStream.instances = []
  mockApi({})
  const response = await fetch('/api/jobs/j1/events?after=2', { headers: { 'X-Argus-Token': 't' } })
  const source = MockEventStream.instances[0]
  expect(source.url).toBe('/api/jobs/j1/events?after=2')
  expect(source.headers.get('X-Argus-Token')).toBe('t')
  expect(response.headers.get('Content-Type')).toBe('text/event-stream')
  const reading = response.text()
  await source.emit({ seq: 3, time: 't', message: 'm' })
  await source.emitEnd({ id: 'j1' })
  expect(await reading).toBe('id: 3\ndata: {"seq":3,"time":"t","message":"m"}\n\nevent: end\ndata: {"id":"j1"}\n\n')
})

test('MockEventStream delivers nothing after it closed, and an abort errors the body', async () => {
  const closed = new MockEventStream('/api/jobs/j1/events')
  const reading = closed.response.text()
  await closed.send('data: 1\n\n')
  await closed.close()
  await closed.send('data: 2\n\n')
  expect(await reading).toBe('data: 1\n\n')

  const controller = new AbortController()
  const aborted = new MockEventStream('/api/jobs/j1/events', { signal: controller.signal })
  const pending = aborted.response.text()
  controller.abort()
  await expect(pending).rejects.toThrow()
  expect(aborted.aborted).toBe(true)
  expect(aborted.closed).toBe(true)
})
