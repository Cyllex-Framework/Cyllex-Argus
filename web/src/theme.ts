/**
 * The product's accent colour, applied once at boot.
 *
 * This file exists for one reason: the vendored `cyllex-design.generated.css` declares
 * `--accent-color: #9333ea` on `:root` — purple — and overrides Tailwind's `purple-*` classes to
 * read from it. Argus deliberately does not use purple accents, so something has to set these
 * variables before the first paint. Editing the vendored stylesheet is not that something: it is
 * generated upstream, and the next re-vendor would silently bring the purple back.
 *
 * There used to be a theme picker here with six presets. It was removed — a CTI tool's accent
 * colour is not a decision worth putting in front of an operator, and the menu it needed was
 * occupying the one corner of the header that should hold something useful.
 */

/** Neutral silver. The same values the old `silver` preset applied, which was the default. */
const ACCENT = {
  accent: '#c0c0c0',
  accentHover: '#e0e0e0',
  accentText: '#1a1a1e',
  bgPrimary: '#1a1a1e',
  bgSecondary: '#242428',
  bgTertiary: '#2e2e34',
} as const

/** Write the accent and base greys onto `:root`. Idempotent; safe to call more than once. */
export function applyAccent(root: HTMLElement = document.documentElement): void {
  root.style.setProperty('--accent-color', ACCENT.accent)
  root.style.setProperty('--accent-hover', ACCENT.accentHover)
  root.style.setProperty('--accent-light', `${ACCENT.accent}33`)
  root.style.setProperty('--accent-border', `${ACCENT.accent}80`)
  root.style.setProperty('--accent-text', ACCENT.accentText)
  root.style.setProperty('--bg-primary', ACCENT.bgPrimary)
  root.style.setProperty('--bg-secondary', ACCENT.bgSecondary)
  root.style.setProperty('--bg-tertiary', ACCENT.bgTertiary)
}

/** The accent, for the rare caller that needs the value rather than the variable. */
export const ACCENT_COLOR = ACCENT.accent
