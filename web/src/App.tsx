import { lazy, Suspense, useEffect } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { SESSION_EXPIRED_EVENT, TOKEN_STORAGE_KEY } from './api/client'
import { AppShell } from './components/AppShell'
import { NotFound } from './components/NotFound'
import { Loading } from './components/QueryState'
import { LoginPage } from './features/auth/LoginPage'
import { DashboardPage } from './features/dashboard/DashboardPage'
import { DocumentsPage } from './features/documents/DocumentsPage'
import { DocumentViewerPage } from './features/documents/DocumentViewerPage'
import { InvestigationDetailPage } from './features/investigations/InvestigationDetailPage'
import { InvestigationReport } from './features/investigations/InvestigationReport'
import { InvestigationsPage } from './features/investigations/InvestigationsPage'
import { LogsPage } from './features/logs/LogsPage'
import { QueryTargetsPage } from './features/query/QueryTargetsPage'
import { SettingsPage } from './features/settings/SettingsPage'
import { SourcesPage } from './features/sources/SourcesPage'
import { ThreatHistoryPage } from './features/threats/ThreatHistoryPage'
import { ThreatProfilePage } from './features/threats/ThreatProfilePage'
import { ThreatsPage } from './features/threats/ThreatsPage'
import { AccountPage } from './features/account/AccountPage'
import { UsersPage } from './features/users/UsersPage'
import { WatchersPage } from './features/watchers/WatchersPage'

// Cytoscape is the heaviest dependency and only the threat profile and the investigation dashboard need it, so both load as their own chunks.
const InvestigationDashboardPage = lazy(() => import('./features/investigations/DashboardPage').then((m) => ({ default: m.DashboardPage })))
const ThreatGraphCard = lazy(() => import('./features/threats/ThreatGraph').then((m) => ({ default: m.ThreatGraphCard })))

const graphSlot = (id: string) => (
  <Suspense fallback={<Loading />}>
    <ThreatGraphCard id={id} />
  </Suspense>
)

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="/threats" element={<ThreatsPage />} />
      <Route path="/threats/:id" element={<ThreatProfilePage graphSlot={graphSlot} />} />
      <Route path="/threats/:id/history" element={<ThreatHistoryPage />} />
      <Route path="/investigations" element={<InvestigationsPage />} />
      <Route path="/investigations/:id" element={<InvestigationDetailPage />} />
      <Route path="/investigations/:id/dashboard" element={<Suspense fallback={<Loading />}><InvestigationDashboardPage /></Suspense>} />
      <Route path="/investigations/:id/report" element={<InvestigationReport />} />
      <Route path="/watchers" element={<WatchersPage />} />
      <Route path="/schedules" element={<Navigate to="/watchers" replace />} />
      <Route path="/documents" element={<DocumentsPage />} />
      <Route path="/documents/:id" element={<DocumentViewerPage />} />
      <Route path="/logs" element={<LogsPage />} />
      <Route path="/sources" element={<SourcesPage />} />
      <Route path="/query/targets" element={<QueryTargetsPage />} />
      <Route path="/settings" element={<SettingsPage />} />
      <Route path="/users" element={<UsersPage />} />
      <Route path="/account" element={<AccountPage />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}

export function App() {
  useEffect(() => {
    // On a 401 the api client already cleared the stale token from localStorage. The right UX
    // from here is "operator must re-authenticate", NOT a terminal "server died" screen that
    // blocks even the login route. Hard-navigate to /login so the SPA re-mounts clean against
    // an empty localStorage; LoginPage then probes /api/auth/status and decides whether to
    // render the form or the "no admin configured" fallback copy. Guard against bouncing when
    // the current page is already /login (e.g. a 401 from the login call itself — handled
    // locally by LoginPage, not by this global).
    const onExpired = () => {
      if (window.location.pathname.endsWith('/login')) return
      const base = import.meta.env.BASE_URL.endsWith('/')
        ? import.meta.env.BASE_URL
        : `${import.meta.env.BASE_URL}/`
      window.location.assign(`${base}login?reason=session_expired`)
    }
    window.addEventListener(SESSION_EXPIRED_EVENT, onExpired)
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired)
  }, [])
  return (
    <Routes>
      {/* /login renders outside the AppShell: no header, no tabs, full-bleed background photo. */}
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="*"
        element={
          <RequireAuth>
            <AppShell>
              <AppRoutes />
            </AppShell>
          </RequireAuth>
        }
      />
    </Routes>
  )
}

/** No token in localStorage → send the operator to /login. The login screen is the only path
 *  to the dashboard; the token is obtained by POSTing credentials to /api/auth/login. */
function RequireAuth({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const hasToken = (() => {
    try {
      return !!localStorage.getItem(TOKEN_STORAGE_KEY)
    } catch {
      return false
    }
  })()
  if (!hasToken) {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />
  }
  return <>{children}</>
}
