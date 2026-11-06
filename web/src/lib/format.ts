/** Local date and time for a timestamp from the API, or "-" when it is missing or not a valid date. */
export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString()
}

const CALENDAR_DATE = /^(\d{4})-(\d{2})-(\d{2})$/

/**
 * Local date (no time) for a value from the API, or "-" when it is missing or not a valid date.
 * A plain `YYYY-MM-DD` is read as that calendar day, not as UTC midnight, so it never slips a day west of UTC.
 */
export function formatDate(value: string | null | undefined): string {
  if (!value) return '-'
  const match = CALENDAR_DATE.exec(value)
  let date: Date
  if (match) {
    const [year, month, day] = [Number(match[1]), Number(match[2]), Number(match[3])]
    date = new Date(year, month - 1, day)
    // new Date() rolls 2025-02-30 over to March; a date that does not exist is not a date.
    if (date.getFullYear() !== year || date.getMonth() !== month - 1 || date.getDate() !== day) return '-'
  } else {
    date = new Date(value)
  }
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleDateString()
}

/** 12_345 → "12.3k", 12_345_678 → "12.3M". Below 1k returns the number as-is. */
export function compactNumber(value: number): string {
  if (!Number.isFinite(value) || value < 0) return '0'
  if (value < 1_000) return String(value)
  if (value < 1_000_000) return `${(value / 1_000).toFixed(value < 10_000 ? 1 : 0)}k`
  if (value < 1_000_000_000) return `${(value / 1_000_000).toFixed(value < 10_000_000 ? 1 : 0)}M`
  return `${(value / 1_000_000_000).toFixed(1)}B`
}

/** 0.004 → "<$0.01", 0.42 → "$0.42", 12.3456 → "$12.35". */
export function formatCost(usd: number): string {
  if (!Number.isFinite(usd) || usd <= 0) return 'free'
  if (usd < 0.01) return '<$0.01'
  return `$${usd.toFixed(2)}`
}
