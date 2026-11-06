import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { isActiveJob, jobLabel, jobPage, useCurrentUser, useJobs, useRefreshWhenJobsEnd, useServerTime } from '../api/hooks'
import { logout as revokeSession } from '../api/client'
import { WatchersMenu } from './WatchersMenu'

/** The gear, drawn inline: one icon is not worth a dependency. */
function GearIcon({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg aria-hidden="true" className={className} viewBox="0 0 20 20" fill="currentColor">
      <path fillRule="evenodd" clipRule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.53 1.53 0 0 1-2.29.95c-1.37-.84-2.95.74-2.11 2.11.6.98.13 2.26-.95 2.29-1.56.38-1.56 2.6 0 2.98a1.53 1.53 0 0 1 .95 2.29c-.84 1.37.74 2.95 2.11 2.11a1.53 1.53 0 0 1 2.29.95c.38 1.56 2.6 1.56 2.98 0a1.53 1.53 0 0 1 2.29-.95c1.37.84 2.95-.74 2.11-2.11a1.53 1.53 0 0 1 .95-2.29c1.56-.38 1.56-2.6 0-2.98a1.53 1.53 0 0 1-.95-2.29c.84-1.37-.74-2.95-2.11-2.11a1.53 1.53 0 0 1-2.29-.95ZM10 13a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" />
    </svg>
  )
}

/** Clock face, drawn inline to match the gear. */
function ClockIcon({ className = 'w-3.5 h-3.5' }: { className?: string }) {
  return (
    <svg aria-hidden="true" className={className} viewBox="0 0 20 20" fill="none" stroke="currentColor"
      strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="10" cy="10" r="7" />
      <path d="M10 6v4l2.5 2" />
    </svg>
  )
}

/** Live server clock in UTC. Watchers run on the server's clock (cron is evaluated with
 *  `datetime.now(UTC)`), so the operator sets schedules against this, not the browser's time. */
function ServerClock() {
  const { now, tz } = useServerTime()
  // toISOString() is always UTC → HH:MM:SS without pulling in a date library.
  const time = now ? now.toISOString().slice(11, 19) : '--:--:--'
  return (
    <span className="flex items-center gap-1.5 text-sm text-gray-400 tabular-nums"
      title="Server time (UTC) — watchers run on this clock.">
      <ClockIcon />
      <span>{time} {tz}</span>
    </span>
  )
}

/** Exit arrow, drawn inline to match the gear. */
function LogoutIcon({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg aria-hidden="true" className={className} viewBox="0 0 20 20" fill="none" stroke="currentColor"
      strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 17H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3" />
      <path d="M13 14l4-4-4-4" />
      <path d="M17 10H8" />
    </svg>
  )
}

export function AppHeader() {
  const { data: jobs } = useJobs()
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { data: currentUser } = useCurrentUser()
  useRefreshWhenJobsEnd()
  const running = jobs?.find((job) => job.state === 'running') ?? jobs?.findLast(isActiveJob)

  const [loggingOut, setLoggingOut] = useState(false)

  // Revoke the session server-side, drop the query cache so a later login never flashes the
  // previous session's data, and return to the login screen. The revoke is a network round-trip,
  // so hold a pending flag across it: the button disables itself (clear feedback, and a second
  // click can't fire a second logout). `finally` restores the flag in the rare case navigation
  // did not unmount us (revoke errors are already swallowed in the client).
  async function logout() {
    if (loggingOut) return
    setLoggingOut(true)
    try {
      await revokeSession()
      queryClient.clear()
      navigate('/login', { replace: true })
    } finally {
      setLoggingOut(false)
    }
  }
  return (
    <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <img src="/assets/argus-logo.png" alt="Cyllex Argus"
               className="h-10 w-auto select-none" draggable={false} />
          <div className="sr-only">
            <div className="text-xl font-semibold tracking-wide">Cyllex Argus</div>
            <div className="text-sm">AI-powered adversary intelligence</div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {running ? (
            <Link to={jobPage(running)} className="flex items-center gap-2 text-sm text-gray-300 hover:text-white">
              <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" aria-hidden="true" />
              {jobLabel(running)}
            </Link>
          ) : (
            <span className="flex items-center gap-2 text-sm text-gray-500">
              <span className="w-2 h-2 rounded-full bg-gray-500" aria-hidden="true" />
              Idle
            </span>
          )}
          {currentUser && <ServerClock />}
          {currentUser && (
            <Link to="/account" className="text-sm text-gray-400 hover:text-white" title="Account & password">
              <span className="text-gray-200">{currentUser.username}</span>
              <span className="text-gray-500"> · {currentUser.role}</span>
            </Link>
          )}
          {currentUser && <WatchersMenu />}
          {currentUser?.role === 'admin' && (
            <Link to="/users" aria-current={pathname.startsWith('/users') ? 'page' : undefined}
              className={`flex items-center gap-2 text-sm rounded px-2 py-1 border transition-colors ${
                pathname.startsWith('/users')
                  ? 'border-gray-500 bg-gray-700 text-white'
                  : 'border-gray-700 text-gray-300 hover:border-gray-500 hover:bg-gray-700 hover:text-white active:bg-gray-600'
              }`}>
              <span className="hidden sm:inline">Users</span>
            </Link>
          )}
          {/* Settings is operator+ (it can change provider keys and sources); readers don't see
              it. It sits here rather than in the Operations menu because it is reached often. */}
          {currentUser?.role !== 'reader' && (
            <Link to="/settings" aria-current={pathname.startsWith('/settings') ? 'page' : undefined}
              className={`flex items-center gap-2 text-sm rounded px-2 py-1 border transition-colors ${
                pathname.startsWith('/settings')
                  ? 'border-gray-500 bg-gray-700 text-white'
                  : 'border-gray-700 text-gray-300 hover:border-gray-500 hover:bg-gray-700 hover:text-white active:bg-gray-600'
              }`}>
              <GearIcon />
              <span className="hidden sm:inline">Settings</span>
            </Link>
          )}
          <button type="button" onClick={logout} disabled={loggingOut}
            className="flex items-center gap-2 text-sm rounded px-2 py-1 border border-gray-700 text-gray-300 hover:border-gray-500 hover:bg-gray-700 hover:text-white active:bg-gray-600 transition-colors disabled:opacity-60 disabled:cursor-not-allowed">
            <LogoutIcon />
            <span className="hidden sm:inline">{loggingOut ? 'Logging out…' : 'Log out'}</span>
          </button>
        </div>
      </div>
    </header>
  )
}
