import { formatDate, formatDateTime } from './format'

test.each([[''], ['garbage'], [null], [undefined]])('formatDateTime(%j) is a dash', (value) => {
  expect(formatDateTime(value)).toBe('-')
})

test('formatDateTime formats a valid ISO timestamp', () => {
  const text = formatDateTime('2026-09-29T10:00:00+00:00')
  expect(text).not.toBe('-')
  expect(text).toBe(new Date('2026-09-29T10:00:00+00:00').toLocaleString())
})

test.each([[''], ['garbage'], ['2025-13-40'], ['2025-02-30'], [null], [undefined]])('formatDate(%j) is a dash', (value) => {
  expect(formatDate(value)).toBe('-')
})

test('formatDate keeps a plain calendar date on the same day in any time zone', () => {
  expect(formatDate('2025-01-10')).toBe(new Date(2025, 0, 10).toLocaleDateString())
})

test('formatDate formats a full timestamp as a local date', () => {
  const stamp = '2026-09-29T10:00:00+00:00'
  expect(formatDate(stamp)).toBe(new Date(stamp).toLocaleDateString())
})
