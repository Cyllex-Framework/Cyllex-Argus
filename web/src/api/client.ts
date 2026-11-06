export const SESSION_EXPIRED_EVENT = 'argus:session-expired'
export const TOKEN_STORAGE_KEY = 'argus.token'
const TOKEN_HEADER = 'X-Argus-Token'

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

function storedToken(): string | null {
  try {
    return window.localStorage.getItem(TOKEN_STORAGE_KEY)
  } catch {
    return null
  }
}

async function errorMessage(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json()
    if (body && typeof body === 'object' && typeof (body as { error?: unknown }).error === 'string') {
      return (body as { error: string }).error
    }
  } catch {
    // not JSON: keep the generic message
  }
  return `Request failed (${response.status})`
}

/**
 * Every API call goes through here: it adds the token header (and the CSRF header on non-GET requests) and turns a
 * 401 into the session-expired event. Cookies are never sent: the API does not use them. Returns the raw response,
 * so callers can read a stream or a file; a non-OK status throws an `ApiError` with the server's message.
 */
export async function apiRequest(path: string, init: RequestInit = {}): Promise<Response> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)
  if (method !== 'GET' && method !== 'HEAD') headers.set('X-Argus-CSRF', '1')
  const token = storedToken()
  if (token) headers.set(TOKEN_HEADER, token)
  const response = await fetch(path, { ...init, method, headers, credentials: 'omit' })
  if (response.status === 401) {
    // Clear the stale token BEFORE firing the event so that whatever handles the redirect sees
    // an empty localStorage — otherwise RequireAuth would still see "has token", re-render the
    // dashboard, which fires more API calls, which fire more 401s. The event tells the App shell
    // to hard-navigate to /login.
    try { localStorage.removeItem(TOKEN_STORAGE_KEY) } catch { /* storage disabled */ }
    window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT))
    throw new ApiError(401, 'Session expired')
  }
  if (!response.ok) throw new ApiError(response.status, await errorMessage(response))
  return response
}

/**
 * Log out: revoke the session server-side, then forget the token locally. The local clear runs
 * even if the network call fails, so the browser never stays "logged in" against a dead session.
 */
export async function logout(): Promise<void> {
  try {
    await apiRequest('/api/auth/logout', { method: 'POST' })
  } catch {
    // a failed revoke still ends the local session
  }
  try { localStorage.removeItem(TOKEN_STORAGE_KEY) } catch { /* storage disabled */ }
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await apiRequest(path, init)
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
}

export function postJson<T>(path: string, body: unknown): Promise<T> {
  return apiFetch<T>(path, jsonInit('POST', body))
}

export function putJson<T>(path: string, body: unknown): Promise<T> {
  return apiFetch<T>(path, jsonInit('PUT', body))
}

export function deleteJson<T>(path: string): Promise<T> {
  return apiFetch<T>(path, { method: 'DELETE' })
}

export function queryString(params: Record<string, string | number | boolean | undefined | null>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '' || value === false) continue
    search.set(key, value === true ? '1' : String(value))
  }
  const text = search.toString()
  return text ? `?${text}` : ''
}
