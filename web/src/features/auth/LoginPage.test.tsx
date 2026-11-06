/**
 * Smoke tests for the login screen. The form always renders — the server has no "login disabled"
 * mode now that the URL-fragment bypass has been removed. Covers: form renders, a successful
 * login stores the token and navigates away, and the "wrong password" path renders an alert
 * without firing session-expired.
 */

import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { LoginPage } from './LoginPage'
import { TOKEN_STORAGE_KEY } from '../../api/client'
import { renderWithProviders } from '../../test/utils'

const DASHBOARD = () => <div>Dashboard screen</div>

function render() {
  // authed=false so LoginPage renders without being redirected away by any guard.
  return renderWithProviders(
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/dashboard" element={<DASHBOARD />} />
    </Routes>,
    { route: '/login', authed: false },
  )
}

beforeEach(() => { localStorage.clear() })

afterEach(() => {
  vi.restoreAllMocks()
  localStorage.clear()
})

test('form renders when the server reports login enabled', async () => {
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
    if (String(input).endsWith('/api/auth/status')) {
      return Promise.resolve(new Response(JSON.stringify({ login_enabled: true }), { status: 200 }))
    }
    return Promise.resolve(new Response('{}', { status: 404 }))
  }))
  render()
  expect(await screen.findByLabelText('Username')).toBeInTheDocument()
  expect(screen.getByLabelText('Password')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Login' })).toBeInTheDocument()
  expect(screen.getByText('AI-powered adversary intelligence')).toBeInTheDocument()
})

test('successful login stores the token and navigates to /dashboard', async () => {
  const fetchMock = vi.fn((input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input)
    if (url.endsWith('/api/auth/status')) {
      return Promise.resolve(new Response(JSON.stringify({ login_enabled: true }), { status: 200 }))
    }
    if (url.endsWith('/api/auth/login')) {
      return Promise.resolve(new Response(JSON.stringify({
        success: true,
        data: { token: 'issued-token-xyz', user: { username: 'admin', role: 'admin' } },
      }), { status: 200 }))
    }
    // Unused but keeps TS happy about `init` being read.
    void init
    return Promise.resolve(new Response('{}', { status: 404 }))
  })
  vi.stubGlobal('fetch', fetchMock)
  render()
  await userEvent.type(await screen.findByLabelText('Username'), 'admin')
  await userEvent.type(screen.getByLabelText('Password'), 's3cret')
  await userEvent.click(screen.getByRole('button', { name: 'Login' }))
  await waitFor(() => expect(screen.getByText('Dashboard screen')).toBeInTheDocument())
  expect(localStorage.getItem(TOKEN_STORAGE_KEY)).toBe('issued-token-xyz')
  const loginCall = fetchMock.mock.calls.find(([u]) => String(u).endsWith('/api/auth/login'))!
  const init = loginCall[1] as RequestInit
  expect(init.method).toBe('POST')
  const headers = new Headers(init.headers)
  expect(headers.get('Content-Type')).toBe('application/json')
  expect(headers.get('X-Argus-CSRF')).toBe('1')
})

test('wrong-password 401 shows an alert without firing session-expired', async () => {
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/api/auth/status')) {
      return Promise.resolve(new Response(JSON.stringify({ login_enabled: true }), { status: 200 }))
    }
    if (url.endsWith('/api/auth/login')) {
      return Promise.resolve(new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401 }))
    }
    return Promise.resolve(new Response('{}', { status: 404 }))
  }))
  const expiredListener = vi.fn()
  window.addEventListener('argus:session-expired', expiredListener)
  render()
  await userEvent.type(await screen.findByLabelText('Username'), 'admin')
  await userEvent.type(screen.getByLabelText('Password'), 'wrong')
  await userEvent.click(screen.getByRole('button', { name: 'Login' }))
  await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('Invalid credentials'))
  // No navigation.
  expect(screen.queryByText('Dashboard screen')).not.toBeInTheDocument()
  // And no session-expired event (that would wipe the login state).
  expect(expiredListener).not.toHaveBeenCalled()
  window.removeEventListener('argus:session-expired', expiredListener)
})
