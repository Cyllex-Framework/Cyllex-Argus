import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test } from 'vitest'
import { UsersPage } from './UsersPage'
import { mockApi, renderWithProviders } from '../../test/utils'

const USERS = [
  { id: 1, username: 'admin', role: 'admin', disabled: false, created_at: 't', created_by: null },
  { id: 2, username: 'bob', role: 'operator', disabled: false, created_at: 't', created_by: 1 },
]

const ME_ADMIN = { username: 'admin', role: 'admin' }

function renderPage(extra: Record<string, unknown> = {}) {
  const fetchMock = mockApi({ 'GET /api/auth/me': ME_ADMIN, 'GET /api/users': { users: USERS }, ...extra })
  renderWithProviders(<UsersPage />, { route: '/users', path: '/users' })
  return fetchMock
}

test('lists the users', async () => {
  renderPage()
  expect(await screen.findByText('bob')).toBeInTheDocument()
  expect(screen.getByText('admin', { selector: 'span' })).toBeInTheDocument()  // the username cell, not a role <option>
})

test('creates a user through the API', async () => {
  const fetchMock = renderPage({
    'POST /api/users': { id: 3, username: 'carol', role: 'reader', disabled: false, created_at: 't', created_by: 1 },
  })
  await screen.findByText('bob')
  await userEvent.type(screen.getByLabelText('Username'), 'carol')
  await userEvent.type(screen.getByLabelText('Password'), 'carol-pass1')
  await userEvent.click(screen.getByRole('button', { name: 'Create' }))
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
    expect.stringContaining('/api/users'), expect.objectContaining({ method: 'POST' })))
})

test('a 409 from create surfaces a clear error', async () => {
  renderPage({
    'POST /api/users': new Response(JSON.stringify({ error: 'username already exists' }), { status: 409 }),
  })
  await screen.findByText('bob')
  await userEvent.type(screen.getByLabelText('Username'), 'admin')
  await userEvent.type(screen.getByLabelText('Password'), 'longenough')
  await userEvent.click(screen.getByRole('button', { name: 'Create' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('username already exists')
})

test('delete calls the API for a non-self user', async () => {
  const fetchMock = renderPage({ 'DELETE /api/users/2': new Response(null, { status: 204 }) })
  await screen.findByText('bob')
  await userEvent.click(screen.getByRole('button', { name: 'Delete' }))  // only bob has one; admin is self
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
    expect.stringContaining('/api/users/2'), expect.objectContaining({ method: 'DELETE' })))
})

test('a non-admin is told they cannot manage users', async () => {
  mockApi({ 'GET /api/auth/me': { username: 'rae', role: 'reader' }, 'GET /api/users': { users: [] } })
  renderWithProviders(<UsersPage />, { route: '/users', path: '/users' })
  expect(await screen.findByText(/Only an admin can manage users/)).toBeInTheDocument()
})
