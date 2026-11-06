import { ACCENT_COLOR, applyAccent } from './theme'

test('applyAccent writes every CSS variable the vendored stylesheet reads', () => {
  const root = document.createElement('div')
  applyAccent(root)
  for (const name of [
    '--accent-color', '--accent-hover', '--accent-light', '--accent-border', '--accent-text',
    '--bg-primary', '--bg-secondary', '--bg-tertiary',
  ]) {
    expect(root.style.getPropertyValue(name)).not.toBe('')
  }
})

test('the accent is not the vendored purple', () => {
  /**
   * The reason `theme.ts` exists at all. `cyllex-design.generated.css` sets
   * `--accent-color: #9333ea` on `:root` and rewires Tailwind's `purple-*` classes to it, so
   * without this call the interface comes up purple — which this product deliberately is not.
   * The stylesheet is generated upstream, so a re-vendor would reintroduce the default and
   * nothing but this test would notice.
   */
  const root = document.createElement('div')
  applyAccent(root)
  expect(root.style.getPropertyValue('--accent-color')).toBe(ACCENT_COLOR)
  expect(root.style.getPropertyValue('--accent-color').toLowerCase()).not.toBe('#9333ea')
})

test('applyAccent is idempotent', () => {
  const root = document.createElement('div')
  applyAccent(root)
  const first = root.getAttribute('style')
  applyAccent(root)
  expect(root.getAttribute('style')).toBe(first)
})
