export interface Span {
  id: number
  start: number
  end: number
}

export interface Segment {
  text: string
  ids: number[]
}

/** Convert spans from code-point offsets (Python) to UTF-16 indices (JavaScript strings). */
export function toUtf16Spans(text: string, spans: Span[]): Span[] {
  const utf16At: number[] = [0]
  let index = 0
  for (const char of text) {
    index += char.length
    utf16At.push(index)
  }
  const convert = (offset: number) => utf16At[Math.max(0, Math.min(offset, utf16At.length - 1))]
  return spans.map((span) => ({ id: span.id, start: convert(span.start), end: convert(span.end) }))
}

/** Split `text` at every span boundary; each segment lists the ids of the spans that cover it. */
export function segmentText(text: string, spans: Span[]): Segment[] {
  if (!text) return []
  const valid = spans.filter((s) => Number.isInteger(s.start) && Number.isInteger(s.end) && s.start >= 0 && s.end <= text.length && s.start < s.end)
  const cuts = new Set<number>([0, text.length])
  for (const span of valid) {
    cuts.add(span.start)
    cuts.add(span.end)
  }
  const points = [...cuts].sort((a, b) => a - b)
  const segments: Segment[] = []
  for (let i = 0; i < points.length - 1; i++) {
    const from = points[i]
    const to = points[i + 1]
    segments.push({ text: text.slice(from, to), ids: valid.filter((s) => s.start <= from && s.end >= to).map((s) => s.id) })
  }
  return segments
}
