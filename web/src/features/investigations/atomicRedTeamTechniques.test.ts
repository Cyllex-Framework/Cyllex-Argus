import { describe, expect, test } from 'vitest'

import { hasAtomicRedTeamTests } from './atomicRedTeamTechniques'

describe('hasAtomicRedTeamTests', () => {
  test('true for a technique Atomic Red Team covers', () => {
    expect(hasAtomicRedTeamTests('T1059')).toBe(true) // Command and Scripting Interpreter
  })

  test('false for a technique with no atomics — avoids a 404 "Atomic Red Team tests" link', () => {
    expect(hasAtomicRedTeamTests('T1199')).toBe(false) // Trusted Relationship — not covered
  })

  test('false for an unknown / malformed id', () => {
    expect(hasAtomicRedTeamTests('T9999')).toBe(false)
    expect(hasAtomicRedTeamTests('')).toBe(false)
  })
})
