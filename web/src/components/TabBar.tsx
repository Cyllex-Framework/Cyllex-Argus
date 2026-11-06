import { useEffect, useRef, useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'

export const TAB_ACTIVE = 'tab-btn px-4 py-3 border-b-2 border-purple-500 text-purple-400'
export const TAB_INACTIVE = 'tab-btn px-4 py-3 border-b-2 border-transparent text-gray-400 hover:text-white'

interface Tab {
  to: string
  label: string
}

/**
 * The five places an analyst works. A long row of equal tabs reads as an admin console and makes
 * the operator choose between everything before they have looked at anything; the work itself
 * lives in these five, and everything that configures or audits the tool sits one click away
 * under "Operations". Watchers is primary because it is where new intelligence surfaces.
 */
export const PRIMARY_TABS: readonly Tab[] = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/threats', label: 'Threats' },
  { to: '/investigations', label: 'Investigations' },
  { to: '/watchers', label: 'Watchers' },
] as const

/** Plumbing: needed regularly, but not while reading intelligence. */
export const OPERATIONS_TABS: readonly Tab[] = [
  { to: '/documents', label: 'Documents' },
  { to: '/query/targets', label: 'Query' },
  { to: '/logs', label: 'Logs' },
  { to: '/sources', label: 'Sources' },
] as const

export const TABS = [...PRIMARY_TABS, ...OPERATIONS_TABS] as const

const isOn = (pathname: string, to: string) => pathname === to || pathname.startsWith(`${to}/`)

export function TabBar() {
  const { pathname } = useLocation()
  return (
    <nav className="bg-gray-800 border-b border-gray-700 px-6">
      <div className="flex gap-1 items-stretch">
        {PRIMARY_TABS.map((tab) => {
          const active = isOn(pathname, tab.to)
          return (
            <NavLink key={tab.to} to={tab.to} className={() => (active ? TAB_ACTIVE : TAB_INACTIVE)}
              aria-current={active ? 'page' : undefined}>
              {tab.label}
            </NavLink>
          )
        })}
        <OperationsMenu pathname={pathname} />
      </div>
    </nav>
  )
}

/** The operations pages behind one tab. Marks itself active (and names the page it is on)
 *  whenever one of them is open, so the operator is never lost inside a collapsed menu. */
function OperationsMenu({ pathname }: { pathname: string }) {
  const [open, setOpen] = useState(false)
  const container = useRef<HTMLDivElement>(null)
  const current = OPERATIONS_TABS.find((tab) => isOn(pathname, tab.to)) ?? null

  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') setOpen(false) }
    const onClick = (event: MouseEvent) => {
      if (!container.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onClick)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onClick)
    }
  }, [open])

  // Closing on navigation: the menu stays mounted across route changes, so without this a
  // pick would leave the panel hanging open over the page it just opened.
  useEffect(() => { setOpen(false) }, [pathname])

  return (
    <div className="relative flex" ref={container}>
      <button type="button" aria-haspopup="menu" aria-expanded={open}
        aria-current={current ? 'page' : undefined}
        onClick={() => setOpen((o) => !o)}
        className={`${current ? TAB_ACTIVE : TAB_INACTIVE} flex items-center gap-1.5`}>
        <span>Operations</span>
        {current && <span className="text-xs opacity-70">· {current.label}</span>}
        <svg aria-hidden="true" className={`w-3 h-3 transition-transform ${open ? 'rotate-180' : ''}`}
          viewBox="0 0 20 20" fill="currentColor">
          <path d="M5 7l5 6 5-6H5z" />
        </svg>
      </button>
      {open && (
        <ul role="menu" aria-label="Operations"
          className="absolute left-0 top-full w-52 border border-gray-700 bg-gray-900 shadow-xl z-50 py-1">
          {OPERATIONS_TABS.map((tab) => {
            const active = isOn(pathname, tab.to)
            return (
              <li key={tab.to} role="none">
                <NavLink to={tab.to} role="menuitem" aria-current={active ? 'page' : undefined}
                  className={`block px-3 py-2 text-sm border-l-2 ${
                    active
                      ? 'border-white bg-gray-800 text-white font-semibold'
                      : 'border-transparent text-gray-300 hover:bg-gray-800 hover:text-white'
                  }`}>
                  {tab.label}
                </NavLink>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
