import { ApiError, apiFetch, apiRequest, postJson, queryString, SESSION_EXPIRED_EVENT, TOKEN_STORAGE_KEY } from './client'
import { mockApi } from '../test/utils'

beforeEach(() => localStorage.clear())

test('GET sends no CSRF header; POST sends it', async () => {
  const fetchMock = mockApi({ 'GET /api/overview': { ok: 1 }, 'POST /api/jobs': { id: 'j1' } })
  await apiFetch('/api/overview')
  await postJson('/api/jobs', { kind: 'attack_update' })
  const [, getInit] = fetchMock.mock.calls[0]
  const [, postInit] = fetchMock.mock.calls[1]
  expect(new Headers(getInit?.headers).get('X-Argus-CSRF')).toBeNull()
  expect(new Headers(postInit?.headers).get('X-Argus-CSRF')).toBe('1')
  expect(new Headers(postInit?.headers).get('Content-Type')).toBe('application/json')
})

test('every request carries the stored token in a header and never sends cookies', async () => {
  localStorage.setItem(TOKEN_STORAGE_KEY, 'tok-1')
  const fetchMock = mockApi({ 'GET /api/overview': { ok: 1 }, 'POST /api/jobs': { id: 'j1' } })
  await apiFetch('/api/overview')
  await postJson('/api/jobs', { kind: 'attack_update' })
  for (const [, init] of fetchMock.mock.calls) {
    expect(new Headers(init?.headers).get('X-Argus-Token')).toBe('tok-1')
    expect(init?.credentials).toBe('omit')
  }
})

test('without a stored token no token header is sent, and the 401 reads as an expired session', async () => {
  const fetchMock = mockApi({ 'GET /api/overview': new Response(JSON.stringify({ error: 'session required' }), { status: 401 }) })
  const listener = vi.fn()
  window.addEventListener(SESSION_EXPIRED_EVENT, listener)
  await expect(apiFetch('/api/overview')).rejects.toMatchObject({ status: 401 })
  expect(new Headers(fetchMock.mock.calls[0][1]?.headers).has('X-Argus-Token')).toBe(false)
  expect(listener).toHaveBeenCalledTimes(1)
  window.removeEventListener(SESSION_EXPIRED_EVENT, listener)
})

test('apiRequest returns the raw response so callers can read a stream or a blob', async () => {
  localStorage.setItem(TOKEN_STORAGE_KEY, 'tok-1')
  mockApi({ 'GET /api/file': new Response('hello', { status: 200, headers: { 'Content-Type': 'text/plain' } }) })
  const response = await apiRequest('/api/file', { headers: { Accept: 'text/plain' } })
  expect(await response.text()).toBe('hello')
})

test('apiRequest throws the server error for a non-OK response', async () => {
  mockApi({ 'GET /api/file': new Response(JSON.stringify({ error: 'unknown threat' }), { status: 404 }) })
  await expect(apiRequest('/api/file')).rejects.toMatchObject({ status: 404, message: 'unknown threat' })
})

test('errors carry the server message and status', async () => {
  mockApi({ 'GET /api/threats/x': new Response(JSON.stringify({ error: 'unknown threat' }), { status: 404 }) })
  await expect(apiFetch('/api/threats/x')).rejects.toMatchObject({ status: 404, message: 'unknown threat' })
})

test('non-JSON errors fall back to a generic message', async () => {
  mockApi({ 'GET /api/overview': new Response('<html>oops</html>', { status: 502 }) })
  await expect(apiFetch('/api/overview')).rejects.toMatchObject({ status: 502, message: 'Request failed (502)' })
})

test('401 dispatches the session-expired event', async () => {
  mockApi({ 'GET /api/overview': new Response(JSON.stringify({ error: 'session required' }), { status: 401 }) })
  const listener = vi.fn()
  window.addEventListener(SESSION_EXPIRED_EVENT, listener)
  await expect(apiFetch('/api/overview')).rejects.toBeInstanceOf(ApiError)
  expect(listener).toHaveBeenCalledTimes(1)
  window.removeEventListener(SESSION_EXPIRED_EVENT, listener)
})

test('with storage blocked, no token is sent and the request lands at the 401 path', async () => {
  // The pre-login URL-fragment token has been removed; without a successful /api/auth/login
  // there is simply no token to send. A blocked localStorage therefore shows up as a 401 flow,
  // exactly as if no login had happened — not as a silent header-leak from some fallback cache.
  const getItem = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked') })
  const fetchMock = mockApi({ 'GET /api/overview': new Response(JSON.stringify({ error: 'session required' }), { status: 401 }) })
  await expect(apiFetch('/api/overview')).rejects.toMatchObject({ status: 401 })
  expect(new Headers(fetchMock.mock.calls[0][1]?.headers).has('X-Argus-Token')).toBe(false)
  getItem.mockRestore()
})

test('queryString drops empty values and encodes booleans as 1', () => {
  expect(queryString({ q: 'octo tempest', type: '', catalog: true, depth: 2, skip: false })).toBe('?q=octo+tempest&catalog=1&depth=2')
  expect(queryString({ q: '' })).toBe('')
})
