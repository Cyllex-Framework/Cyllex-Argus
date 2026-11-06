import { Link } from 'react-router-dom'

export function NotFound() {
  return (
    <div className="card p-8 text-center">
      <h1 className="text-lg font-semibold mb-2">Page not found</h1>
      <Link to="/dashboard" className="text-purple-400 hover:underline text-sm">Back to the dashboard</Link>
    </div>
  )
}
