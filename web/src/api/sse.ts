/**
 * A `text/event-stream` reader for `fetch` bodies. `EventSource` cannot send headers, and the API token must travel in
 * one (never in a URL), so the job stream is read with `fetch` and parsed here, following the WHATWG SSE rules the
 * server relies on: `data:` (multi-line), `event:`, `id:`, comment lines (`: keepalive`) and LF, CRLF or CR endings.
 */
export interface SseMessage {
  event: string
  data: string
  id: string | null
}

const LINE_END = /\r\n|\r|\n/g

/** Incremental parser: push decoded text as it arrives, get back the events it completed. */
export class SseParser {
  private buffer = ''
  private data: string[] = []
  private event = ''
  private lastId: string | null = null

  /** `final` marks the end of the stream: a trailing CR is then a line end, not half of a CRLF. */
  push(text: string, final = false): SseMessage[] {
    this.buffer += text
    const messages: SseMessage[] = []
    let consumed = 0
    LINE_END.lastIndex = 0
    for (let match = LINE_END.exec(this.buffer); match; match = LINE_END.exec(this.buffer)) {
      // A CR at the very end may be the first half of a CRLF split across chunks: wait for the next one.
      if (!final && match[0] === '\r' && match.index === this.buffer.length - 1) break
      this.line(this.buffer.slice(consumed, match.index), messages)
      consumed = match.index + match[0].length
    }
    this.buffer = this.buffer.slice(consumed)
    return messages
  }

  private line(line: string, messages: SseMessage[]): void {
    if (line === '') {
      if (this.data.length) messages.push({ event: this.event || 'message', data: this.data.join('\n'), id: this.lastId })
      this.data = []
      this.event = ''
      return
    }
    if (line.startsWith(':')) return // a comment, such as the server's keepalive
    const colon = line.indexOf(':')
    const field = colon < 0 ? line : line.slice(0, colon)
    let value = colon < 0 ? '' : line.slice(colon + 1)
    if (value.startsWith(' ')) value = value.slice(1)
    if (field === 'data') this.data.push(value)
    else if (field === 'event') this.event = value
    else if (field === 'id' && !value.includes('\0')) this.lastId = value
  }
}

/**
 * Read a stream body to its end, calling `onMessage` for each complete event. An event still unterminated when the
 * stream ends is dropped, as the spec says. Returns true when `onMessage` returned true to stop early (the stream is
 * then cancelled), false when the stream ended by itself; rejects when the stream errors or is aborted.
 */
export async function readEventStream(
  body: ReadableStream<Uint8Array>,
  onMessage: (message: SseMessage) => boolean | void,
): Promise<boolean> {
  const reader = body.getReader()
  const decoder = new TextDecoder()
  const parser = new SseParser()
  try {
    for (;;) {
      const { done, value } = await reader.read()
      const text = done ? decoder.decode() : decoder.decode(value, { stream: true })
      for (const message of parser.push(text, done)) {
        if (onMessage(message) === true) {
          await reader.cancel().catch(() => undefined)
          return true
        }
      }
      if (done) return false
    }
  } finally {
    reader.releaseLock()
  }
}
