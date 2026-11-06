import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test } from 'vitest'
import { AccountPage } from './AccountPage'
import { mockApi, renderWithProviders } from '../../test/utils'

function renderPage(extra: Record<string, unknown> = {}) {
  const fetchMock = mockApi({ 'GET /api/auth/me': { username: 'rae', role: 'reader' }, ...extra })
  renderWithProviders(<AccountPage />, { route: '/account', path: '/account' })
  return fetchMock
}

test('submits the current and new password to the API', async () => {
  const fetchMock = renderPage({ 'PUT /api/users/me/password': new Response(null, { status: 204 }) })
  await screen.findByText('rae')
  await userEvent.type(screen.getByLabelText('Current password'), 'old-pass1')
  await userEvent.type(screen.getByLabelText('New password'), 'new-pass12')
  await userEvent.click(screen.getByRole('button', { name: 'Update password' }))
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
    expect.stringContaining('/api/users/me/password'), expect.objectContaining({ method: 'PUT' })))
  expect(await screen.findByText('Password updated.')).toBeInTheDocument()
})

test('a wrong current password surfaces the error', async () => {
  renderPage({
    'PUT /api/users/me/password': new Response(JSON.stringify({ error: 'current password is incorrect' }), { status: 400 }),
  })
  await screen.findByText('rae')
  await userEvent.type(screen.getByLabelText('Current password'), 'wrong')
  await userEvent.type(screen.getByLabelText('New password'), 'new-pass12')
  await userEvent.click(screen.getByRole('button', { name: 'Update password' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('current password is incorrect')
})
