/**
 * Argus login screen.
 *
 * Visual clone of the Cyllex login (same layout, same silver accent, same full-bleed background
 * photo) with the Argus logo and tagline swapped in. Submits credentials to
 * `POST /api/auth/login`; on 200 it stores the returned session token in `localStorage` under
 * the same key the rest of the SPA already reads, and redirects to the dashboard.
 *
 * The login screen is the only path to the dashboard — there is no URL-fragment bypass.
 * A connectivity pre-flight to `/api/auth/status` surfaces a "could not reach the server"
 * message when the API is unreachable; the form itself always renders.
 */

import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { TOKEN_STORAGE_KEY } from '../../api/client'
import './login.css'

interface LoginResponse {
  success: boolean
  data: {
    token: string
    user: { username: string; role: string }
  }
}

export function LoginPage() {
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const expired = params.get('reason') === 'session_expired'
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [statusError, setStatusError] = useState<string | null>(null)

  useEffect(() => {
    // Connectivity pre-flight: surfaces a "could not reach the server" message when the API
    // is down. Direct fetch on purpose — the apiFetch wrapper would route a 401 through the
    // session-expired handler, which is wrong for the login page.
    fetch('/api/auth/status', { credentials: 'omit' })
      .then((r) => {
        if (!r.ok) throw new Error(`status endpoint returned ${r.status}`)
      })
      .catch((exc: unknown) => setStatusError(exc instanceof Error ? exc.message : String(exc)))
  }, [])

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      // Direct fetch — the apiRequest helper turns a 401 into the SESSION_EXPIRED_EVENT, which
      // would be wrong semantics for "operator typed the wrong password".
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Argus-CSRF': '1' },
        credentials: 'omit',
        body: JSON.stringify({ username, password }),
      })
      if (!response.ok) {
        let message = `Login failed (${response.status})`
        try {
          const body: unknown = await response.json()
          if (body && typeof body === 'object' && typeof (body as { error?: unknown }).error === 'string') {
            message = (body as { error: string }).error
          }
        } catch {
          /* non-JSON error body */
        }
        setError(message)
        return
      }
      const resp = (await response.json()) as LoginResponse
      try {
        localStorage.setItem(TOKEN_STORAGE_KEY, resp.data.token)
      } catch {
        // Private mode / disabled storage: the token lives only in-memory for this tab.
      }
      navigate('/dashboard', { replace: true })
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setPending(false)
    }
  }

  return (
    <div
      className="login-scope min-h-screen flex items-center justify-center px-4"
      style={{
        backgroundImage: `url(${import.meta.env.BASE_URL}assets/auth-bg.jpg)`,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat',
        backgroundAttachment: 'fixed',
      }}
    >
      <div className="w-full max-w-md">
        <div className="auth-wrap">
          <div className="text-center mb-8">
            <img
              src={`${import.meta.env.BASE_URL}assets/argus-logo.png`}
              alt="Cyllex Argus"
              className="h-auto w-auto max-w-[260px] mx-auto mb-2"
            />
            <p className="text-gray-300 mt-2">AI-powered adversary intelligence</p>
          </div>

          {statusError && (
            <p role="alert" className="text-red-400 text-sm text-center mb-4">
              Could not reach the server: {statusError}
            </p>
          )}
          <form onSubmit={submit} className="space-y-4">
            {expired && !error && (
              <p className="text-amber-300 text-sm text-center">
                Your session expired or the server was restarted. Log in again to continue.
              </p>
            )}
            <div>
              <label className="block text-sm text-gray-400 mb-2" htmlFor="login-username">
                Username
              </label>
              <input
                id="login-username"
                type="text"
                autoComplete="username"
                className="login-input w-full rounded px-4 py-3 text-gray-200"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                required
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-2" htmlFor="login-password">
                Password
              </label>
              <input
                id="login-password"
                type="password"
                autoComplete="current-password"
                className="login-input w-full rounded px-4 py-3 text-gray-200"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </div>
            {error && (
              <p role="alert" className="text-red-400 text-sm">{error}</p>
            )}
            <button
              type="submit"
              disabled={pending}
              className="login-btn w-full py-3 rounded font-semibold text-gray-200"
            >
              {pending ? 'Signing in…' : 'Login'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
