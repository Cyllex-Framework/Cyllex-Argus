import type { ReactElement } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { vi } from 'vitest'
import { TOKEN_STORAGE_KEY } from '../api/client'
import type { JobEvent, LlmSettings } from '../api/types'

/** The LLM block of GET /api/settings for a default install. */
export const LLM_SETTINGS: LlmSettings = {
  provider: 'claude-code-cli',
  model: null,
  timeout_seconds: 600,
  claude_binary: 'claude',
  ollama: { base_url: 'http://127.0.0.1:11434', model: 'qwen2.5:32b-instruct', keep_alive: '10m' },
  anthropic: { api_key: '', model: 'claude-sonnet-5-5', base_url: 'https://api.anthropic.com', anthropic_version: '2023-06-01' },
  openai: { api_key: '', model: 'gpt-4o', base_url: 'https://api.openai.com/v1', organization: '' },
  agents: {
    triage: { provider: '', model: '' },
    analyst: { provider: '', model: '' },
    summary: { provider: '', model: '' },
  },
  search_provider: 'claude-code-cli',
  restart_required: false,
}

export function renderWithProviders(
  ui: ReactElement,
  { route = '/', path = '*', authed = true }: { route?: string; path?: string; authed?: boolean } = {},
) {
  // Pre-seed the session token by default so RequireAuth lets App render straight into the
  // routes under test. Only inject a default when the test hasn't already set its own — some
  // tests preseed a specific token value and then assert against it. LoginPage tests pass
  // `authed: false` to exercise the no-token path.
  try {
    if (!authed) {
      localStorage.removeItem(TOKEN_STORAGE_KEY)
    } else if (localStorage.getItem(TOKEN_STORAGE_KEY) === null) {
      localStorage.setItem(TOKEN_STORAGE_KEY, 'test-token-xyz')
    }
  } catch { /* ignore */ }
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  const result = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[route]}>
        <Routes>
          <Route path={path} element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return { ...result, queryClient }
}

type Handler = unknown | ((init: RequestInit, url: string) => Response | MockEventStream | unknown)

const JOB_EVENTS = /^\/api\/jobs\/[^/]+\/events$/

function toResponse(value: unknown): Response {
  if (value instanceof MockEventStream) return value.response
  if (value instanceof Response) return value.clone() // a Body can be read only once; clone so a route can be fetched repeatedly
  return new Response(JSON.stringify(value), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

/**
 * Benign defaults for endpoints that side-render on many pages (SettingsPage mounts
 * EnrichersCard which queries `/api/enrichers`). Returning an empty list here keeps a test
 * focused on an unrelated card from drowning in "no mock for /api/enrichers" noise. Explicit
 * `routes` always override these.
 */
const DEFAULT_ROUTES: Record<string, Handler> = {
  'GET /api/auth/me': { username: 'admin', role: 'admin' },
  'GET /api/watchers': [],
  'GET /api/watchers/changes': [],
  'GET /api/enrichers': { enrichers: [] },
  'GET /api/settings/misp': { servers: [] },
  'GET /api/settings/taxii': { servers: [] },
  'GET /api/settings/webhooks': { webhooks: [] },
}

/**
 * Stub fetch. Keys look like "GET /api/overview" or "GET /api/threats?q=octo" (exact query match when given).
 * A job event stream with no route of its own is served by a new `MockEventStream`.
 */
export function mockApi(routes: Record<string, Handler>) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(typeof input === 'string' ? input : input.toString(), 'http://127.0.0.1')
    const method = (init.method ?? 'GET').toUpperCase()
    const exact = `${method} ${url.pathname}${url.search}`
    const loose = `${method} ${url.pathname}`
    let handler: Handler | undefined =
      exact in routes ? routes[exact] : loose in routes ? routes[loose] : undefined
    if (handler === undefined) handler = DEFAULT_ROUTES[loose]
    if (handler === undefined) {
      if (method === 'GET' && JOB_EVENTS.test(url.pathname)) return new MockEventStream(`${url.pathname}${url.search}`, init).response
      return new Response(JSON.stringify({ error: `no mock for ${exact}` }), { status: 404 })
    }
    // A handler may answer later (return a promise) to hold a request open.
    return toResponse(typeof handler === 'function' ? await (handler as (i: RequestInit, u: string) => unknown)(init, `${url.pathname}${url.search}`) : handler)
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

/**
 * Let a stream reader and the React updates it triggers run (wrap the call in `await act(...)`). Two timer turns:
 * a dropped stream reconnects after a (test: zero) delay timer, and the new connection should exist afterwards.
 */
async function settle(): Promise<void> {
  for (let turn = 0; turn < 2; turn++) await new Promise((resolve) => setTimeout(resolve, 0))
}

/**
 * A server-sent event stream served as a streamed fetch response. Tests push SSE text into it; `emit`/`emitEnd`
 * format events as the server does. `closed` turns true when either side ends it (the client cancels or aborts).
 */
export class MockEventStream {
  static instances: MockEventStream[] = []
  readonly url: string
  readonly init: RequestInit
  readonly response: Response
  closed = false
  private controller!: ReadableStreamDefaultController<Uint8Array>
  private readonly encoder = new TextEncoder()

  constructor(url: string, init: RequestInit = {}) {
    this.url = url
    this.init = init
    const body = new ReadableStream<Uint8Array>({
      start: (controller) => {
        this.controller = controller
      },
      cancel: () => {
        this.closed = true
      },
    })
    init.signal?.addEventListener('abort', () => this.end(new DOMException('The operation was aborted.', 'AbortError')))
    this.response = new Response(body, { status: 200, headers: { 'Content-Type': 'text/event-stream' } })
    MockEventStream.instances.push(this)
  }

  get headers(): Headers {
    return new Headers(this.init.headers)
  }

  get aborted(): boolean {
    return this.init.signal?.aborted ?? false
  }

  /** Push raw SSE text (any chunking), then let the reader catch up. */
  async send(text: string): Promise<void> {
    if (!this.closed) this.controller.enqueue(this.encoder.encode(text))
    await settle()
  }

  emit(data: JobEvent): Promise<void> {
    return this.send(`id: ${data.seq}\ndata: ${JSON.stringify(data)}\n\n`)
  }

  /** The server's final event; it then closes the stream. */
  async emitEnd(job: unknown): Promise<void> {
    await this.send(`event: end\ndata: ${JSON.stringify(job)}\n\n`)
    await this.close()
  }

  /** The body ends normally (e.g. the server stopped mid-job). */
  async close(): Promise<void> {
    this.end()
    await settle()
  }

  /** The connection breaks (a network error while reading). */
  async fail(): Promise<void> {
    this.end(new TypeError('network error'))
    await settle()
  }

  private end(error?: unknown): void {
    if (this.closed) return
    this.closed = true
    if (error === undefined) this.controller.close()
    else this.controller.error(error)
  }
}
