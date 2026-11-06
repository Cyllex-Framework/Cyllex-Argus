import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { LlmSettings } from '../../api/types'
import { LLM_SETTINGS, mockApi, renderWithProviders } from '../../test/utils'
import { SettingsPage } from './SettingsPage'

const settings = (llm: Partial<LlmSettings> = {}) => ({
  attack: { present: true, techniques: 10, groups: 2, software: 3 },
  claude: { found: true },
  config: {},
  home: 'C:/argus',
  llm: { ...LLM_SETTINGS, ...llm },
  known_models: {
    'anthropic-api': ['claude-opus-5-5', 'claude-sonnet-5-5'],
    'openai-api': ['gpt-4o', 'gpt-4o-mini'],
  },
})

const OLLAMA: Partial<LlmSettings> = {
  provider: 'ollama',
  search_provider: 'disabled',
  timeout_seconds: 900,
  ollama: { base_url: 'http://10.0.0.5:11434', model: 'llama3.1:8b', keep_alive: '30m' },
}

const bodyOf = (fetchMock: ReturnType<typeof mockApi>, method: string, path: string) => {
  const call = fetchMock.mock.calls.find(([url, init]) => String(url) === path && (init?.method ?? 'GET') === method)
  return call ? JSON.parse(String((call[1] as RequestInit).body)) : undefined
}

test('the form shows the current values', async () => {
  mockApi({ 'GET /api/settings': settings({ model: 'opus' }) })
  renderWithProviders(<SettingsPage />)
  expect(await screen.findByLabelText('Claude Code CLI', { selector: 'input[name="provider"]' })).toBeChecked()
  expect(screen.getByLabelText('Model')).toHaveValue('opus')
  expect(screen.getByLabelText('claude binary')).toHaveValue('claude')
  expect(screen.getByLabelText('timeout_seconds')).toHaveValue(600)
  expect(screen.getByLabelText('Claude Code CLI', { selector: 'input[name="search"]' })).toBeChecked()
  expect(screen.getByText(/Limits and scoring are edited in/)).toBeInTheDocument()
  expect(screen.queryByText(/Restart/)).not.toBeInTheDocument()
})

test('the form shows the Ollama values and a disabled search provider', async () => {
  mockApi({ 'GET /api/settings': settings(OLLAMA) })
  renderWithProviders(<SettingsPage />)
  expect(await screen.findByLabelText('Base URL')).toHaveValue('http://10.0.0.5:11434')
  expect(screen.getByLabelText('Model')).toHaveValue('llama3.1:8b')
  expect(screen.getByLabelText('Keep alive')).toHaveValue('30m')
  expect(screen.getByLabelText('timeout_seconds')).toHaveValue(900)
  expect(screen.getByLabelText(/Disabled/)).toBeChecked()
})

test('changing the provider toggles the fields', async () => {
  mockApi({ 'GET /api/settings': settings() })
  renderWithProviders(<SettingsPage />)
  await screen.findByLabelText('claude binary')
  expect(screen.queryByLabelText('Base URL')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Test connection' })).not.toBeInTheDocument()
  await userEvent.click(screen.getByLabelText('Ollama (local)'))
  expect(screen.getByLabelText('Base URL')).toHaveValue('http://127.0.0.1:11434')
  expect(screen.getByLabelText('Keep alive')).toHaveValue('10m')
  expect(screen.getByLabelText('timeout_seconds')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Test connection' })).toBeInTheDocument()
  expect(screen.queryByLabelText('claude binary')).not.toBeInTheDocument()
})

test('save sends the form as a PUT and refreshes the settings', async () => {
  let current = settings()
  const fetchMock = mockApi({
    'GET /api/settings': () => current,
    'PUT /api/settings/llm': (init: RequestInit) => {
      const body = JSON.parse(String(init.body))
      current = settings({ ...OLLAMA, model: body.model, restart_required: true })
      return current
    },
  })
  renderWithProviders(<SettingsPage />)
  await userEvent.click(await screen.findByLabelText('Ollama (local)'))
  const url = screen.getByLabelText('Base URL')
  await userEvent.clear(url)
  await userEvent.type(url, 'http://10.0.0.5:11434')
  const model = screen.getByLabelText('Model')
  await userEvent.clear(model)
  await userEvent.type(model, 'llama3.1:8b')
  const keepAlive = screen.getByLabelText('Keep alive')
  await userEvent.clear(keepAlive)
  await userEvent.type(keepAlive, '30m')
  const timeout = screen.getByLabelText('timeout_seconds')
  await userEvent.clear(timeout)
  await userEvent.type(timeout, '900')
  await userEvent.click(screen.getByLabelText(/Disabled/))
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(bodyOf(fetchMock, 'PUT', '/api/settings/llm')).toBeDefined())
  expect(bodyOf(fetchMock, 'PUT', '/api/settings/llm')).toEqual({
    provider: 'ollama',
    model: null,
    timeout_seconds: 900,
    claude_binary: 'claude',
    ollama: { base_url: 'http://10.0.0.5:11434', model: 'llama3.1:8b', keep_alive: '30m' },
    // The anthropic + openai sub-blocks always travel in the body; the server preserves the
    // stored key when the UI echoes back the mask (an empty string here means no key stored).
    anthropic: { api_key: '', model: 'claude-sonnet-5-5', base_url: 'https://api.anthropic.com', anthropic_version: '2023-06-01' },
    openai: { api_key: '', model: 'gpt-4o', base_url: 'https://api.openai.com/v1', organization: '' },
    agents: {
      triage: { provider: '', model: '' },
      analyst: { provider: '', model: '' },
      summary: { provider: '', model: '' },
    },
    search: { provider: 'disabled' },
  })
  expect(await screen.findByText(/for these changes to take effect/)).toBeInTheDocument()
  const gets = fetchMock.mock.calls.filter(([u, init]) => String(u) === '/api/settings' && (init?.method ?? 'GET') === 'GET')
  expect(gets.length).toBeGreaterThan(1)
})

test('save is disabled while the request is in flight and shows the API error', async () => {
  let release: () => void = () => {}
  mockApi({
    'GET /api/settings': settings(),
    'PUT /api/settings/llm': () => new Promise((resolve) => {
      release = () => resolve(new Response(JSON.stringify({ error: 'timeout_seconds must be between 10 and 3600' }), { status: 400 }))
    }),
  })
  renderWithProviders(<SettingsPage />)
  await screen.findByLabelText('claude binary')
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled())
  release()
  expect(await screen.findByRole('alert')).toHaveTextContent('timeout_seconds must be between 10 and 3600')
  expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled()
})

test('discard resets the form to the stored values', async () => {
  mockApi({ 'GET /api/settings': settings({ model: 'opus' }) })
  renderWithProviders(<SettingsPage />)
  const model = await screen.findByLabelText('Model')
  await userEvent.clear(model)
  await userEvent.type(model, 'sonnet')
  await userEvent.click(screen.getByLabelText('Ollama (local)'))
  await userEvent.click(screen.getByRole('button', { name: 'Discard' }))
  expect(screen.getByLabelText('Model')).toHaveValue('opus')
  expect(screen.getByLabelText('Claude Code CLI', { selector: 'input[name="provider"]' })).toBeChecked()
})

test('test connection shows the models and whether the configured one is installed', async () => {
  const fetchMock = mockApi({
    'GET /api/settings': settings(OLLAMA),
    'POST /api/settings/llm/test': { ok: true, models: ['llama3.1:8b', 'mistral:latest'], model_present: true },
  })
  renderWithProviders(<SettingsPage />)
  await userEvent.click(await screen.findByRole('button', { name: 'Test connection' }))
  expect(await screen.findByText(/Connected\. 2 models available/)).toBeInTheDocument()
  expect(screen.getByText(/is installed/)).toBeInTheDocument()
  expect(screen.getByText('llama3.1:8b, mistral:latest')).toBeInTheDocument()
  expect(bodyOf(fetchMock, 'POST', '/api/settings/llm/test')).toEqual({
    provider: 'ollama', ollama: { base_url: 'http://10.0.0.5:11434', model: 'llama3.1:8b' },
  })
})

test('test connection says when the model is missing', async () => {
  mockApi({
    'GET /api/settings': settings(OLLAMA),
    'POST /api/settings/llm/test': { ok: true, models: ['mistral:latest'], model_present: false },
  })
  renderWithProviders(<SettingsPage />)
  await userEvent.click(await screen.findByRole('button', { name: 'Test connection' }))
  expect(await screen.findByText(/is not installed/)).toBeInTheDocument()
})

test('test connection shows a failure inline', async () => {
  mockApi({
    'GET /api/settings': settings(OLLAMA),
    'POST /api/settings/llm/test': { ok: false, error: 'cannot connect to Ollama at http://10.0.0.5:11434' },
  })
  renderWithProviders(<SettingsPage />)
  await userEvent.click(await screen.findByRole('button', { name: 'Test connection' }))
  expect(await screen.findByText(/Connection failed: cannot connect to Ollama/)).toBeInTheDocument()
})

test('selecting Anthropic API reveals the key field and the model/base-url inputs', async () => {
  mockApi({ 'GET /api/settings': settings() })
  renderWithProviders(<SettingsPage />)
  await screen.findByLabelText('claude binary')
  await userEvent.click(screen.getByLabelText('Anthropic API'))
  // API key field is a password input and starts empty on a never-touched config.
  const key = screen.getByLabelText(/API key/)
  expect(key).toHaveAttribute('type', 'password')
  expect(key).toHaveValue('')
  expect(screen.getByLabelText('Model')).toHaveValue('claude-sonnet-5-5')
  expect(screen.getByLabelText('Base URL')).toHaveValue('https://api.anthropic.com')
  expect(screen.getByLabelText('anthropic-version')).toHaveValue('2023-06-01')
  // The claude-cli-only fields disappear.
  expect(screen.queryByLabelText('claude binary')).not.toBeInTheDocument()
})

test('selecting OpenAI API reveals the key, model, base-url and org inputs', async () => {
  mockApi({ 'GET /api/settings': settings() })
  renderWithProviders(<SettingsPage />)
  await screen.findByLabelText('claude binary')
  await userEvent.click(screen.getByLabelText('OpenAI API'))
  const key = screen.getByLabelText(/API key/)
  expect(key).toHaveAttribute('type', 'password')
  expect(screen.getByLabelText('Model')).toHaveValue('gpt-4o')
  expect(screen.getByLabelText('Base URL')).toHaveValue('https://api.openai.com/v1')
  expect(screen.getByLabelText('Organization (optional)')).toHaveValue('')
})

test('a stored Anthropic key renders as the mask and clears on focus so typing replaces it', async () => {
  mockApi({ 'GET /api/settings': settings({
    provider: 'anthropic-api',
    anthropic: { api_key: '••••••••', model: 'claude-sonnet-5-5', base_url: 'https://api.anthropic.com', anthropic_version: '2023-06-01' },
  })})
  renderWithProviders(<SettingsPage />)
  const key = await screen.findByLabelText(/API key/) as HTMLInputElement
  expect(key).toHaveValue('••••••••')
  // Operator clicks the field → the mask clears so what they type replaces (not extends) the stored value.
  await userEvent.click(key)
  expect(key).toHaveValue('')
})

test('saving with an unchanged Anthropic key echoes the mask back so the server keeps it', async () => {
  let current = settings({
    provider: 'anthropic-api',
    anthropic: { api_key: '••••••••', model: 'claude-sonnet-5-5', base_url: 'https://api.anthropic.com', anthropic_version: '2023-06-01' },
  })
  const fetchMock = mockApi({
    'GET /api/settings': () => current,
    'PUT /api/settings/llm': () => current,
  })
  renderWithProviders(<SettingsPage />)
  await screen.findByLabelText(/API key/)
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(bodyOf(fetchMock, 'PUT', '/api/settings/llm')).toBeDefined())
  const body = bodyOf(fetchMock, 'PUT', '/api/settings/llm')
  expect(body.anthropic.api_key).toBe('••••••••')  // server interprets this as "keep stored"
})

test('OpenAI test connection POSTs the api/key + model + base_url + org', async () => {
  const fetchMock = mockApi({
    'GET /api/settings': settings({ provider: 'openai-api' }),
    'POST /api/settings/llm/test': { ok: true, models: ['gpt-4o', 'gpt-4o-mini'], model_present: true },
  })
  renderWithProviders(<SettingsPage />)
  await userEvent.type(await screen.findByLabelText(/API key/), 'sk-test')
  await userEvent.click(screen.getByRole('button', { name: 'Test connection' }))
  await waitFor(() => expect(bodyOf(fetchMock, 'POST', '/api/settings/llm/test')).toBeDefined())
  const body = bodyOf(fetchMock, 'POST', '/api/settings/llm/test')
  expect(body.provider).toBe('openai-api')
  expect(body.openai.api_key).toBe('sk-test')
  expect(body.openai.model).toBe('gpt-4o')
  expect(await screen.findByText(/Connected\. 2 models available/)).toBeInTheDocument()
  expect(screen.getByText(/is available/)).toBeInTheDocument()
})

test('per-agent section is collapsed when nothing is overridden', async () => {
  mockApi({ 'GET /api/settings': settings() })
  renderWithProviders(<SettingsPage />)
  await screen.findByLabelText('claude binary')
  const summary = screen.getByText('Per-agent model overrides')
  // The <details> element is closed by default — JSDOM does keep its children in the DOM, but
  // the browser hides them. `.open` is the signal the operator relies on; the hint about
  // "optional — use the base provider everywhere" sits right next to it so the state is visible.
  expect(summary.closest('details')!.open).toBe(false)
  expect(screen.getByText(/optional — use the base provider everywhere/)).toBeInTheDocument()
})

test('per-agent section auto-expands when a slot is already overridden on load', async () => {
  mockApi({ 'GET /api/settings': settings({
    agents: {
      triage: { provider: 'openai-api', model: 'gpt-4o-mini' },
      analyst: { provider: '', model: '' },
      summary: { provider: '', model: '' },
    },
  }) })
  renderWithProviders(<SettingsPage />)
  const triageProvider = await screen.findByLabelText('Triage provider') as HTMLSelectElement
  expect(triageProvider.value).toBe('openai-api')
  const triageModel = screen.getByLabelText('Triage model') as HTMLInputElement
  expect(triageModel.value).toBe('gpt-4o-mini')
})

test('saving a per-agent override sends it in the PUT body', async () => {
  let current = settings()
  const fetchMock = mockApi({
    'GET /api/settings': () => current,
    'PUT /api/settings/llm': (init: RequestInit) => {
      const body = JSON.parse(String(init.body))
      current = settings({ agents: body.agents, restart_required: true })
      return current
    },
  })
  renderWithProviders(<SettingsPage />)
  // Expand the collapsible — click the summary line.
  await userEvent.click(await screen.findByText('Per-agent model overrides'))
  await userEvent.selectOptions(screen.getByLabelText('Triage provider'), 'openai-api')
  await userEvent.type(screen.getByLabelText('Triage model'), 'gpt-4o-mini')
  await userEvent.selectOptions(screen.getByLabelText('Analyst provider'), 'anthropic-api')
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(bodyOf(fetchMock, 'PUT', '/api/settings/llm')).toBeDefined())
  const body = bodyOf(fetchMock, 'PUT', '/api/settings/llm')
  expect(body.agents.triage).toEqual({ provider: 'openai-api', model: 'gpt-4o-mini' })
  expect(body.agents.analyst).toEqual({ provider: 'anthropic-api', model: '' })
  // Untouched slots travel back as empty — the server interprets that as "use base".
  expect(body.agents.summary).toEqual({ provider: '', model: '' })
})

test('the Anthropic model field offers the priced ids as a dropdown and warns on a CLI alias', async () => {
  mockApi({ 'GET /api/settings': settings({ provider: 'anthropic-api', model: null }) })
  renderWithProviders(<SettingsPage />)
  // The model field is a combobox backed by a datalist of the server's priced ids.
  const modelField = await screen.findByLabelText('Model')
  const listId = modelField.getAttribute('list')
  expect(listId).toBeTruthy()
  const datalist = document.getElementById(listId!)
  expect(datalist?.querySelectorAll('option')).toHaveLength(2)
  expect(datalist?.querySelector('option[value="claude-opus-5-5"]')).toBeInTheDocument()
  // A bare CLI alias is flagged; the config default (a full id) is not.
  expect(screen.queryByText(/Claude Code CLI short name/)).not.toBeInTheDocument()
  await userEvent.clear(modelField)
  await userEvent.type(modelField, 'opus')
  expect(await screen.findByText(/Claude Code CLI short name/)).toBeInTheDocument()
  await userEvent.clear(modelField)
  await userEvent.type(modelField, 'claude-opus-5-5')
  expect(screen.queryByText(/Claude Code CLI short name/)).not.toBeInTheDocument()
})

test('a hidden base-model override surfaces on an API provider and can be cleared', async () => {
  // The exact trap: provider switched to the API but [llm] model still holds a CLI short name.
  let current = settings({ provider: 'anthropic-api', model: 'opus' })
  const fetchMock = mockApi({
    'GET /api/settings': () => current,
    'PUT /api/settings/llm': () => {
      current = settings({ provider: 'anthropic-api', model: null, restart_required: true })
      return current
    },
  })
  renderWithProviders(<SettingsPage />)
  // The override is announced with its value, the CLI-alias warning fires, and a Clear button shows.
  expect(await screen.findByText(/base model override is set/)).toBeInTheDocument()
  expect(screen.getByText('opus')).toBeInTheDocument()
  expect(screen.getByText(/Claude Code CLI short name/)).toBeInTheDocument()
  const clear = screen.getByRole('button', { name: /Clear override/ })
  await userEvent.click(clear)
  // Cleared from the form, so the banner is gone.
  expect(screen.queryByText(/base model override is set/)).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(bodyOf(fetchMock, 'PUT', '/api/settings/llm')).toBeDefined())
  // The top-level model is sent as null — the server clears [llm] model.
  expect(bodyOf(fetchMock, 'PUT', '/api/settings/llm').model).toBeNull()
})

test('the restart banner shows when the server reports restart_required', async () => {
  mockApi({ 'GET /api/settings': settings({ restart_required: true }) })
  renderWithProviders(<SettingsPage />)
  expect(await screen.findByText(/for these changes to take effect/)).toBeInTheDocument()
  expect(screen.getByText(/still using the previous configuration/)).toBeInTheDocument()
})
