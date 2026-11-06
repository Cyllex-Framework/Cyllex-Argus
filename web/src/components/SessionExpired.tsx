export function SessionExpired() {
  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <div className="card p-8 max-w-md text-center">
        <img src="/assets/argus-logo.png" alt="Cyllex Argus"
             className="h-12 w-auto mx-auto mb-4 select-none" draggable={false} />
        <h1 className="text-lg font-semibold mb-2">Session expired</h1>
        <p className="text-gray-400 text-sm">
          This page is no longer connected to your local Argus. Run <code className="mono">argus serve</code> again and
          open the link it prints.
        </p>
      </div>
    </div>
  )
}
