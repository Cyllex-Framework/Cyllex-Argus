import '@testing-library/jest-dom/vitest'
import { configure } from '@testing-library/react'
import { STREAM_RETRY } from './api/useJobEvents'

if (typeof Element !== 'undefined' && !Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = () => {}
}

configure({ asyncUtilTimeout: 5000 })

// A dropped job stream reconnects at once in tests instead of after a real delay.
STREAM_RETRY.delayMs = 0
