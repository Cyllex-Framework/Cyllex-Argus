import { useState, type FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
import { ApiError, putJson } from '../../api/client'
import { useCurrentUser } from '../../api/hooks'
import { Card } from '../../components/Card'

/** Available to every signed-in user (reader included): change your own password. */
export function AccountPage() {
  const { data: me } = useCurrentUser()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [done, setDone] = useState(false)
  const change = useMutation({
    mutationFn: () => putJson('/api/users/me/password', { current_password: current, new_password: next }),
    onSuccess: () => { setDone(true); setCurrent(''); setNext('') },
  })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    setDone(false)
    change.mutate()
  }

  return (
    <div className="max-w-xl mx-auto p-6 space-y-6">
      <h1 className="text-xl font-semibold">Account</h1>
      {me && (
        <p className="text-gray-400 text-sm">
          Signed in as <span className="text-gray-200">{me.username}</span> ({me.role}).
        </p>
      )}
      <Card title="Change password">
        <form onSubmit={submit} className="space-y-3 max-w-sm">
          <label className="flex flex-col text-sm gap-1">
            <span className="text-gray-400">Current password</span>
            <input type="password" className="login-input rounded px-3 py-2 text-gray-200" value={current}
              onChange={(e) => setCurrent(e.target.value)} required />
          </label>
          <label className="flex flex-col text-sm gap-1">
            <span className="text-gray-400">New password</span>
            <input type="password" minLength={8} className="login-input rounded px-3 py-2 text-gray-200" value={next}
              onChange={(e) => setNext(e.target.value)} required />
          </label>
          <button type="submit" disabled={change.isPending}
            className="rounded px-4 py-2 bg-purple-700 hover:bg-purple-600 text-white text-sm disabled:opacity-50">
            Update password
          </button>
          {change.error && (
            <p role="alert" className="text-red-400 text-sm">
              {change.error instanceof ApiError ? change.error.message : 'Could not update password'}
            </p>
          )}
          {done && <p className="text-green-400 text-sm">Password updated.</p>}
        </form>
      </Card>
    </div>
  )
}
