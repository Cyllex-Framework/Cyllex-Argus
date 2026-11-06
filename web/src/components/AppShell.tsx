import type { ReactNode } from 'react'
import { AppHeader } from './AppHeader'
import { TabBar } from './TabBar'

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <>
      {/* `.app-chrome` is hidden by `@media print` in the dossier so the report prints clean. */}
      <div className="app-chrome">
        <AppHeader />
        <TabBar />
      </div>
      <main className="p-6">{children}</main>
    </>
  )
}
