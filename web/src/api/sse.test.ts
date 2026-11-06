import { readEventStream, SseParser, type SseMessage } from './sse'

function streamOf(chunks: (string | Uint8Array)[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder()
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(typeof chunk === 'string' ? encoder.encode(chunk) : chunk)
      controller.close()
    },
  })
}

test('parses data, id and event fields; an event ends at a blank line', () => {
  const parser = new SseParser()
  expect(parser.push('id: 1\ndata: {"seq":1}\n\nevent: end\ndata: null\n\n')).toEqual([
    { event: 'message', data: '{"seq":1}', id: '1' },
    { event: 'end', data: 'null', id: '1' }, // the last event id carries over, as in the spec
  ])
})

test('joins multi-line data with newlines and strips only one leading space', () => {
  expect(new SseParser().push('data:first\ndata:  second\ndata\n\n')).toEqual([{ event: 'message', data: 'first\n second\n', id: null }])
})

test('ignores comments such as keepalives, unknown fields and events without data', () => {
  expect(new SseParser().push(': keepalive\n\nretry: 10\nfoo: bar\n\nevent: end\n\n')).toEqual([])
})

test('handles lines and events split across chunks', () => {
  const parser = new SseParser()
  const seen: SseMessage[] = []
  for (const chunk of ['id: 7\nda', 'ta: {"seq"', ':7}\n', '\n: keep', 'alive\n\n', 'data: x\n']) seen.push(...parser.push(chunk))
  expect(seen).toEqual([{ event: 'message', data: '{"seq":7}', id: '7' }])
  expect(parser.push('\n')).toEqual([{ event: 'message', data: 'x', id: '7' }])
})

test('accepts CRLF and CR line endings, including a CRLF split between chunks', () => {
  const parser = new SseParser()
  // A CR at the end of a chunk may be the first half of a CRLF, so it waits for the next chunk.
  expect(parser.push('data: a\r\n\r\ndata: b\r\r')).toEqual([{ event: 'message', data: 'a', id: null }])
  expect(parser.push('data: c\r')).toEqual([{ event: 'message', data: 'b', id: null }])
  expect(parser.push('\n\r')).toEqual([])
  expect(parser.push('\n')).toEqual([{ event: 'message', data: 'c', id: null }])
})

test('readEventStream decodes UTF-8 split inside a character and delivers each event', async () => {
  const bytes = new TextEncoder().encode('data: café\n\n')
  const seen: SseMessage[] = []
  const stopped = await readEventStream(streamOf([bytes.slice(0, 10), bytes.slice(10), ': keepalive\n\n']), (message) => {
    seen.push(message)
  })
  expect(stopped).toBe(false)
  expect(seen).toEqual([{ event: 'message', data: 'café', id: null }])
})

test('a stream that ends in a bare CR still completes its last event', async () => {
  const seen: SseMessage[] = []
  await readEventStream(streamOf(['data: {"seq":1}\r', '\r']), (message) => { seen.push(message) })
  expect(seen.map((message) => message.data)).toEqual(['{"seq":1}'])
})

test('readEventStream drops an unterminated event when the stream ends', async () => {
  const seen: SseMessage[] = []
  await readEventStream(streamOf(['data: done\n\ndata: partial\n']), (message) => { seen.push(message) })
  expect(seen.map((m) => m.data)).toEqual(['done'])
})

test('readEventStream stops and cancels the stream when the callback says so', async () => {
  let cancelled = false
  const encoder = new TextEncoder()
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode('event: end\ndata: 1\n\ndata: after\n\n'))
    },
    cancel() {
      cancelled = true
    },
  })
  const seen: string[] = []
  const stopped = await readEventStream(body, (message) => {
    seen.push(message.event)
    return message.event === 'end'
  })
  expect(stopped).toBe(true)
  expect(seen).toEqual(['end'])
  expect(cancelled).toBe(true)
})

test('readEventStream rejects when the stream errors', async () => {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.error(new TypeError('network error'))
    },
  })
  await expect(readEventStream(body, () => undefined)).rejects.toThrow('network error')
})
