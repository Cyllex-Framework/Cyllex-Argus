import { segmentText, toUtf16Spans } from './highlight'

const join = (segments: { text: string }[]) => segments.map((s) => s.text).join('')

test('no spans gives one plain segment', () => {
  expect(segmentText('hello', [])).toEqual([{ text: 'hello', ids: [] }])
})

test('empty text gives no segments', () => {
  expect(segmentText('', [{ id: 1, start: 0, end: 3 }])).toEqual([])
})

test('a span splits the text into three segments', () => {
  const segments = segmentText('abcdefgh', [{ id: 7, start: 2, end: 5 }])
  expect(segments).toEqual([
    { text: 'ab', ids: [] },
    { text: 'cde', ids: [7] },
    { text: 'fgh', ids: [] },
  ])
})

test('overlapping spans produce segments covered by both ids', () => {
  const segments = segmentText('abcdefgh', [{ id: 1, start: 1, end: 5 }, { id: 2, start: 3, end: 7 }])
  expect(segments).toEqual([
    { text: 'a', ids: [] },
    { text: 'bc', ids: [1] },
    { text: 'de', ids: [1, 2] },
    { text: 'fg', ids: [2] },
    { text: 'h', ids: [] },
  ])
  expect(join(segments)).toBe('abcdefgh')
})

test('out-of-range, reversed and empty spans are ignored without losing text', () => {
  const text = 'short text'
  const segments = segmentText(text, [
    { id: 1, start: -4, end: 3 },
    { id: 2, start: 5, end: 500 },
    { id: 3, start: 6, end: 2 },
    { id: 4, start: 4, end: 4 },
  ])
  expect(segments).toEqual([{ text, ids: [] }])
})

test('code-point spans from the API are converted to UTF-16 indices', () => {
  const text = '\u{1F600}\u{1F600} called the help desk'
  // Python sees 2 code points before "called"; JavaScript sees 4 UTF-16 units.
  const [span] = toUtf16Spans(text, [{ id: 1, start: 3, end: 9 }])
  expect(text.slice(span.start, span.end)).toBe('called')
  expect(toUtf16Spans('plain', [{ id: 2, start: 1, end: 3 }])).toEqual([{ id: 2, start: 1, end: 3 }])
  expect(toUtf16Spans('ab', [{ id: 3, start: 1, end: 99 }])).toEqual([{ id: 3, start: 1, end: 2 }])
})

test('a span covering the whole text', () => {
  expect(segmentText('abc', [{ id: 9, start: 0, end: 3 }])).toEqual([{ text: 'abc', ids: [9] }])
})
