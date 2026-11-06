import { act, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'
import { App } from './App'
import { SESSION_EXPIRED_EVENT, TOKEN_STORAGE_KEY } from './api/client'
import { mockApi, renderWithProviders } from './test/utils'

const EMPTY_OVERVIEW = {
  counts: { threats: 0, documents: {}, assessments: {}, investigations: 0 },
  recent_investigations: [],
  unrated_publishers: [],
}

test('renders the Cyllex-style shell with the four work tabs and redirects / to the dashboard', async () => {
  mockApi({ 'GET /api/jobs': [], 'GET /api/overview': EMPTY_OVERVIEW })
  renderWithProviders(<App />, { route: '/' })
  expect(screen.getByText('Cyllex Argus')).toBeInTheDocument()
  expect(screen.getByText('AI-powered adversary intelligence')).toBeInTheDocument()
  const tabs = screen.getAllByRole('link').filter((a) => a.className.includes('tab-btn'))
  // The bar carries the four places an analyst works; the operations pages sit behind the
  // Operations menu, so the first glance is a short row of choices instead of everything.
  expect(tabs.map((t) => t.textContent)).toEqual(['Dashboard', 'Threats', 'Investigations', 'Watchers'])
  const active = tabs.find((t) => t.getAttribute('aria-current') === 'page')
  expect(active?.textContent).toBe('Dashboard')
  expect(active?.className).toContain('border-purple-500')
})

test('the Watchers tab opens the watchers page', async () => {
  mockApi({ 'GET /api/jobs': [], 'GET /api/watchers': [], 'GET /api/watchers/changes': [] })
  renderWithProviders(<App />, { route: '/watchers' })
  expect(await screen.findByRole('heading', { name: 'Watchers' })).toBeInTheDocument()
  const tab = screen.getAllByRole('link').find((a) => a.className.includes('tab-btn') && a.textContent === 'Watchers')
  expect(tab).toHaveAttribute('aria-current', 'page')
})

test('the operations pages are one click away behind the Operations menu', async () => {
  mockApi({ 'GET /api/jobs': [], 'GET /api/overview': EMPTY_OVERVIEW })
  renderWithProviders(<App />, { route: '/' })
  expect(screen.queryByRole('menu', { name: 'Operations' })).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: /Operations/ }))
  const items = screen.getAllByRole('menuitem')
  // Settings is not in here: it is the page reached for most often, and the menu was the
  // hardest place to find it. It lives in the header instead.
  expect(items.map((i) => i.textContent)).toEqual(['Documents', 'Query', 'Logs', 'Sources'])
})

test('the retired /schedules route redirects to Watchers', async () => {
  // Watchers absorbed recurring investigations; old /schedules links must still land somewhere sane.
  mockApi({ 'GET /api/jobs': [], 'GET /api/overview': EMPTY_OVERVIEW,
    'GET /api/watchers': [], 'GET /api/watchers/changes': [] })
  renderWithProviders(<App />, { route: '/schedules' })
  expect(await screen.findByRole('heading', { name: 'Watchers' })).toBeInTheDocument()
})

test('Settings is in the header, and says when you are on it', async () => {
  mockApi({ 'GET /api/jobs': [], 'GET /api/overview': EMPTY_OVERVIEW })
  renderWithProviders(<App />, { route: '/' })

  const link = screen.getByRole('link', { name: /Settings/ })
  expect(link).toHaveAttribute('href', '/settings')
  expect(link.closest('header')).not.toBeNull()
  expect(link).not.toHaveAttribute('aria-current')
})

test('the header Settings link marks itself current on the settings page', async () => {
  mockApi({
    'GET /api/jobs': [],
    'GET /api/settings': { attack: { present: true }, claude: { found: true }, config: {}, home: 'C:/argus' },
  })
  renderWithProviders(<App />, { route: '/settings' })
  expect(screen.getByRole('link', { name: /Settings/ })).toHaveAttribute('aria-current', 'page')
})

test('the accent-colour picker is gone from the header', async () => {
  mockApi({ 'GET /api/jobs': [], 'GET /api/overview': EMPTY_OVERVIEW })
  renderWithProviders(<App />, { route: '/' })
  // A CTI tool's accent colour is not a decision worth putting in front of an operator, and the
  // menu was occupying the one corner of the header that should hold something useful.
  expect(screen.queryByRole('button', { name: 'Change theme' })).not.toBeInTheDocument()
})

test('the Operations tab marks itself active and names the page when one of its pages is open', async () => {
  mockApi({
    'GET /api/jobs': [],
    'GET /api/settings': { attack: { present: true }, claude: { found: true }, config: {}, home: 'C:/argus' },
    'GET /api/sources': [],
  })
  renderWithProviders(<App />, { route: '/sources' })
  const trigger = screen.getByRole('button', { name: /Operations/ })
  expect(trigger).toHaveAttribute('aria-current', 'page')
  expect(trigger).toHaveTextContent('Sources')
})

test('header shows the running job', async () => {
  mockApi({
    'GET /api/overview': EMPTY_OVERVIEW,
    'GET /api/jobs': [{ id: 'j1', kind: 'investigate', params: { target: 'Scattered Spider' }, state: 'running',
      created_at: '', started_at: '', finished_at: null, message: null, result: null, events: 1 }],
  })
  renderWithProviders(<App />, { route: '/dashboard' })
  expect(await screen.findByText('Investigating Scattered Spider')).toBeInTheDocument()
})

test.each([
  ['investigate', { target: 'Scattered Spider' }, 'Investigating Scattered Spider', '/investigations'],
  ['investigate', { target: 'Scattered Spider', investigation_id: 3 }, 'Investigating Scattered Spider', '/investigations/3/dashboard'],
  ['resume', { investigation_id: 3 }, 'Resuming investigation #3', '/investigations/3/dashboard'],
  ['ingest', { files: ['a.txt'] }, 'Ingesting 1 file(s)', '/documents'],
  ['attack_update', {}, 'Updating ATT&CK', '/settings'],
  ['recompute', {}, 'Recomputing confidences', '/sources'],
])('the header links a running %s job to the page that shows its progress', async (kind, params, label, href) => {
  mockApi({
    'GET /api/overview': EMPTY_OVERVIEW,
    'GET /api/jobs': [{ id: 'j1', kind, params, state: 'running', created_at: '', started_at: '', finished_at: null, message: null, result: null, events: 1 }],
  })
  renderWithProviders(<App />, { route: '/dashboard' })
  expect(await screen.findByRole('link', { name: label })).toHaveAttribute('href', href)
})

test('a 401 anywhere hard-navigates to /login so the operator can re-authenticate', async () => {
  mockApi({ 'GET /api/jobs': [], 'GET /api/overview': EMPTY_OVERVIEW })
  // jsdom's window.location.assign is non-configurable, so we swap the whole `location` out for
  // a stub. The App's SESSION_EXPIRED handler calls location.assign('/login?reason=…'); assert
  // on that. Restore after so later tests in the file see the real location.
  const originalLocation = window.location
  const assign = vi.fn<(url: string | URL) => void>()
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: { ...originalLocation, assign, pathname: '/dashboard' },
  })
  try {
    renderWithProviders(<App />, { route: '/dashboard' })
    act(() => { window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT)) })
    expect(assign).toHaveBeenCalledWith(expect.stringMatching(/\/login\?reason=session_expired$/))
  } finally {
    Object.defineProperty(window, 'location', { configurable: true, value: originalLocation })
  }
})

test('unknown routes show not found', () => {
  mockApi({ 'GET /api/jobs': [], 'GET /api/overview': EMPTY_OVERVIEW })
  renderWithProviders(<App />, { route: '/nope' })
  expect(screen.getByText('Page not found')).toBeInTheDocument()
})

test('the threat routes render the search page and the profile page', async () => {
  const entity = { id: 'intrusion-set--1', name: 'Scattered Spider', stix_type: 'intrusion-set', external_id: null, attack: true, label: 'Scattered Spider' }
  mockApi({
    'GET /api/jobs': [],
    'GET /api/threats': [{ ...entity, facts: 1 }],
    'GET /api/threats/intrusion-set--1': { entity, aliases: [], facts: [] },
    'GET /api/threats/intrusion-set--1/graph': { nodes: [], edges: [] },
  })
  const search = renderWithProviders(<App />, { route: '/threats' })
  expect(await screen.findByLabelText('Search threats')).toBeInTheDocument()
  search.unmount()
  renderWithProviders(<App />, { route: '/threats/intrusion-set--1' })
  expect(await screen.findByRole('heading', { name: 'Scattered Spider' })).toBeInTheDocument()
  expect(await screen.findByText(/No relationships to draw/)).toBeInTheDocument() // the profile route wires in the graph card
})

test('the document routes render the list and the viewer', async () => {
  const summary = { id: 7, title: 'Deep dive', publisher: 'Mandiant', stage: 'validated', published_at: '2025-01-10',
    retrieved_at: '2025-01-11T10:00:00+00:00', failure_reason: null, location: null }
  mockApi({
    'GET /api/jobs': [],
    'GET /api/documents': [summary],
    'GET /api/documents/7': { ...summary, text: 'Body text', claims: [] },
  })
  const list = renderWithProviders(<App />, { route: '/documents' })
  expect(await screen.findByRole('link', { name: 'Deep dive' })).toHaveAttribute('href', '/documents/7')
  expect(screen.getByLabelText(/files to ingest/i)).toBeInTheDocument()
  list.unmount()
  renderWithProviders(<App />, { route: '/documents/7' })
  expect(await screen.findByRole('heading', { name: 'Deep dive' })).toBeInTheDocument()
  expect(await screen.findByText('Body text')).toBeInTheDocument()
})

test('the investigation routes render the list with its start form and the detail page', async () => {
  const summary = { id: 3, target: 'Scattered Spider', state: 'paused', started_at: '2026-09-29T10:00:00+00:00', finished_at: null,
    collected: true, stage_counts: { validated: 2 } }
  mockApi({
    'GET /api/jobs': [],
    'GET /api/investigations': [summary],
    'GET /api/investigations/3': { ...summary, documents: [], failures: [] },
  })
  const list = renderWithProviders(<App />, { route: '/investigations' })
  expect(await screen.findByRole('link', { name: 'Scattered Spider' })).toHaveAttribute('href', '/investigations/3/dashboard')
  expect(screen.getByLabelText('Threat to investigate')).toBeInTheDocument()
  list.unmount()
  renderWithProviders(<App />, { route: '/investigations/3' })
  expect(await screen.findByRole('heading', { name: /Scattered Spider/ })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Resume' })).toBeInTheDocument()
})

test('Log out clears the session token and returns to the login screen', async () => {
  mockApi({
    'GET /api/jobs': [],
    'GET /api/overview': EMPTY_OVERVIEW,
    'GET /api/auth/status': { login_enabled: true, default_password_in_use: false },
    'POST /api/auth/logout': new Response(null, { status: 204 }),
  })
  renderWithProviders(<App />, { route: '/' })
  expect(localStorage.getItem(TOKEN_STORAGE_KEY)).not.toBeNull()

  await userEvent.click(screen.getByRole('button', { name: /Log out/ }))

  // The session is revoked server-side, the token is forgotten, and we are back on login.
  expect(await screen.findByLabelText('Username')).toBeInTheDocument()
  expect(localStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull()
  expect(screen.queryByRole('button', { name: /Log out/ })).not.toBeInTheDocument()
})

test('Log out disables itself while the request is in flight so a double click cannot fire twice', async () => {
  let release!: () => void
  const held = new Promise<void>((resolve) => { release = resolve })
  const logoutHandler = vi.fn(async () => { await held; return new Response(null, { status: 204 }) })
  mockApi({
    'GET /api/jobs': [],
    'GET /api/overview': EMPTY_OVERVIEW,
    'GET /api/auth/status': { login_enabled: true, default_password_in_use: false },
    'POST /api/auth/logout': logoutHandler,
  })
  renderWithProviders(<App />, { route: '/' })

  const button = await screen.findByRole('button', { name: /Log out/ })
  await userEvent.click(button)

  // The revoke is still in flight (held): the button must be disabled so a second click is a no-op.
  expect(button).toBeDisabled()
  await userEvent.click(button)

  release()
  expect(await screen.findByLabelText('Username')).toBeInTheDocument()
  expect(logoutHandler).toHaveBeenCalledTimes(1)
})

test('a reader sees no write controls: no investigate form, no Settings or Users links', async () => {
  mockApi({
    'GET /api/jobs': [],
    'GET /api/investigations': [],
    'GET /api/auth/me': { username: 'rae', role: 'reader' },
  })
  renderWithProviders(<App />, { route: '/investigations' })
  expect(await screen.findByText('rae')).toBeInTheDocument()  // the header identifies the reader
  expect(screen.queryByLabelText('Threat to investigate')).not.toBeInTheDocument()
  expect(screen.queryByRole('link', { name: /Settings/ })).not.toBeInTheDocument()
  expect(screen.queryByRole('link', { name: /Users/ })).not.toBeInTheDocument()
})
