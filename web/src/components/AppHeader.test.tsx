/**
 * AppHeader: focuses on the server clock. Watchers run on the server's UTC clock, so the header
 * shows that time (ticked locally from an offset), not the browser's — see useServerTime.
 */

import { afterEach, expect, test, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { AppHeader } from './AppHeader'
import { mockApi, renderWithProviders } from '../test/utils'

afterEach(() => { vi.restoreAllMocks() })

test('renders the live server clock labeled UTC beside the user', async () => {
  mockApi({
    'GET /api/auth/me': { username: 'alice', role: 'operator' },
    'GET /api/jobs': [],
    'GET /api/time': { now: '2026-11-02T14:35:12Z', tz: 'UTC' },
  })
  renderWithProviders(<AppHeader />)
  // The clock ticks from the server offset; within the same minute it reads 14:35:ss UTC.
  await waitFor(() => expect(screen.getByText(/14:35:\d\d UTC/)).toBeInTheDocument())
  // The tooltip tells the operator why it is there.
  expect(screen.getByTitle(/Server time \(UTC\) — watchers run on this clock\./)).toBeInTheDocument()
  // The user it sits beside is still shown.
  expect(screen.getByText('alice')).toBeInTheDocument()
})
