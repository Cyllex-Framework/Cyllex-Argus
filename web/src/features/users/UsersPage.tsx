import { useState, type FormEvent } from 'react'
import { ApiError } from '../../api/client'
import {
  roleAtLeast, useCurrentUser, useUserMutations, useUsers,
  type ManagedUser, type Role,
} from '../../api/hooks'
import { Card } from '../../components/Card'
import { ErrorCard, Loading } from '../../components/QueryState'

const ROLES: Role[] = ['reader', 'operator', 'admin']

function message(error: unknown): string {
  if (error instanceof ApiError) return error.message
  return error instanceof Error ? error.message : String(error)
}

/** Admin-only screen to manage web UI users. The server enforces every action; this page just
 *  drives the /api/users endpoints and surfaces their errors (duplicate name, short password,
 *  last-admin guard). */
export function UsersPage() {
  const { data: me } = useCurrentUser()
  const users = useUsers()

  if (!roleAtLeast(me?.role, 'admin')) {
    return (
      <div className="max-w-3xl mx-auto p-6">
        <Card title="Users"><p className="text-gray-400 text-sm">Only an admin can manage users.</p></Card>
      </div>
    )
  }
  if (users.isLoading) return <Loading />
  if (users.error || !users.data) return <ErrorCard error={users.error} />

  return (
    <div className="max-w-3xl mx-auto p-6 space-y-6">
      <h1 className="text-xl font-semibold">Users</h1>
      <CreateUserCard />
      <Card title="All users">
        <ul className="divide-y divide-gray-700/60">
          {users.data.map((user) => (
            <UserRow key={user.id} user={user} isSelf={user.username === me?.username} />
          ))}
        </ul>
      </Card>
    </div>
  )
}

function CreateUserCard() {
  const { create } = useUserMutations()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Role>('reader')

  const submit = (event: FormEvent) => {
    event.preventDefault()
    create.mutate({ username: username.trim(), password, role }, {
      onSuccess: () => { setUsername(''); setPassword('') },
    })
  }

  return (
    <Card title="Create user">
      <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col text-sm gap-1">
          <span className="text-gray-400">Username</span>
          <input className="login-input rounded px-3 py-2 text-gray-200" value={username}
            onChange={(e) => setUsername(e.target.value)} required />
        </label>
        <label className="flex flex-col text-sm gap-1">
          <span className="text-gray-400">Password</span>
          <input type="password" className="login-input rounded px-3 py-2 text-gray-200" value={password}
            onChange={(e) => setPassword(e.target.value)} required />
        </label>
        <label className="flex flex-col text-sm gap-1">
          <span className="text-gray-400">Role</span>
          <select className="login-input rounded px-3 py-2 text-gray-200" value={role}
            onChange={(e) => setRole(e.target.value as Role)}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>
        <button type="submit" disabled={create.isPending}
          className="rounded px-4 py-2 bg-purple-700 hover:bg-purple-600 text-white text-sm disabled:opacity-50">
          Create
        </button>
      </form>
      {create.error && <p role="alert" className="text-red-400 text-sm mt-3">{message(create.error)}</p>}
    </Card>
  )
}

function UserRow({ user, isSelf }: { user: ManagedUser; isSelf: boolean }) {
  const { update, remove, resetPassword } = useUserMutations()
  const [resetting, setResetting] = useState(false)
  const [newPassword, setNewPassword] = useState('')
  const error = update.error || remove.error || resetPassword.error

  const doReset = (event: FormEvent) => {
    event.preventDefault()
    resetPassword.mutate({ id: user.id, password: newPassword }, {
      onSuccess: () => { setResetting(false); setNewPassword('') },
    })
  }

  return (
    <li className="py-3">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-gray-200 font-medium min-w-[8rem]">{user.username}</span>
        <select className="login-input rounded px-2 py-1 text-sm text-gray-200" value={user.role}
          onChange={(e) => update.mutate({ id: user.id, role: e.target.value as Role })}>
          {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        {user.disabled && <span className="text-amber-400 text-xs">disabled</span>}
        <div className="ml-auto flex items-center gap-2 text-sm">
          <button type="button" className="rounded px-2 py-1 border border-gray-700 text-gray-300 hover:text-white"
            onClick={() => update.mutate({ id: user.id, disabled: !user.disabled })}>
            {user.disabled ? 'Enable' : 'Disable'}
          </button>
          <button type="button" className="rounded px-2 py-1 border border-gray-700 text-gray-300 hover:text-white"
            onClick={() => setResetting((v) => !v)}>
            Reset password
          </button>
          {!isSelf && (
            <button type="button" className="rounded px-2 py-1 border border-red-800 text-red-300 hover:text-red-100"
              onClick={() => remove.mutate(user.id)}>
              Delete
            </button>
          )}
        </div>
      </div>
      {resetting && (
        <form onSubmit={doReset} className="mt-2 flex items-center gap-2">
          <input type="password" placeholder="New password" value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="login-input rounded px-3 py-1 text-sm text-gray-200" required />
          <button type="submit" className="rounded px-3 py-1 bg-purple-700 hover:bg-purple-600 text-white text-sm">
            Set
          </button>
        </form>
      )}
      {error && <p role="alert" className="text-red-400 text-sm mt-2">{message(error)}</p>}
    </li>
  )
}
