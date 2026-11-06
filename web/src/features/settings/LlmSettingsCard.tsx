import { useId, useState } from 'react'
import { useSaveLlmSettings, useTestLlm } from '../../api/hooks'
import type { AgentsSettings, LlmProvider, LlmSettings, LlmUpdate, SearchProvider } from '../../api/types'
import { Card } from '../../components/Card'

const MASK_VALUE = '••••••••'
const PROVIDER_LABELS: Record<string, string> = {
  '': 'Use base provider',
  'claude-code-cli': 'Claude Code CLI',
  'ollama': 'Ollama (local)',
  'anthropic-api': 'Anthropic API',
  'openai-api': 'OpenAI API',
}
type AgentName = 'triage' | 'analyst' | 'summary'
const UI_AGENTS: readonly { name: AgentName; label: string; hint: string }[] = [
  { name: 'triage', label: 'Triage', hint: 'yes/no decision, so a cheap model is usually enough.' },
  { name: 'analyst', label: 'Analyst', hint: 'citation-exact extraction, where quality shows.' },
  { name: 'summary', label: 'Summary', hint: 'writes the actor dossier once per finished run.' },
]

interface Form {
  provider: LlmProvider
  model: string
  claudeBinary: string
  timeout: string
  baseUrl: string
  ollamaModel: string
  keepAlive: string
  anthropicKey: string
  anthropicModel: string
  anthropicBaseUrl: string
  anthropicVersion: string
  openaiKey: string
  openaiModel: string
  openaiBaseUrl: string
  openaiOrganization: string
  agents: AgentsSettings
  search: SearchProvider
}

function fromApi(llm: LlmSettings): Form {
  return {
    provider: llm.provider,
    model: llm.model ?? '',
    claudeBinary: llm.claude_binary,
    timeout: String(llm.timeout_seconds),
    baseUrl: llm.ollama.base_url,
    ollamaModel: llm.ollama.model,
    keepAlive: llm.ollama.keep_alive,
    anthropicKey: llm.anthropic.api_key, // may be '' or MASK_VALUE
    anthropicModel: llm.anthropic.model,
    anthropicBaseUrl: llm.anthropic.base_url,
    anthropicVersion: llm.anthropic.anthropic_version,
    openaiKey: llm.openai.api_key,
    openaiModel: llm.openai.model,
    openaiBaseUrl: llm.openai.base_url,
    openaiOrganization: llm.openai.organization,
    agents: {
      triage: { ...llm.agents.triage },
      analyst: { ...llm.agents.analyst },
      summary: { ...llm.agents.summary },
    },
    search: llm.search_provider,
  }
}

function toBody(form: Form): LlmUpdate {
  return {
    provider: form.provider,
    model: form.model.trim() || null,
    timeout_seconds: Number(form.timeout),
    claude_binary: form.claudeBinary,
    ollama: { base_url: form.baseUrl, model: form.ollamaModel, keep_alive: form.keepAlive },
    anthropic: {
      api_key: form.anthropicKey, // the mask round-trips unchanged → server keeps the stored value
      model: form.anthropicModel,
      base_url: form.anthropicBaseUrl,
      anthropic_version: form.anthropicVersion,
    },
    openai: {
      api_key: form.openaiKey,
      model: form.openaiModel,
      base_url: form.openaiBaseUrl,
      organization: form.openaiOrganization,
    },
    agents: form.agents,
    search: { provider: form.search },
  }
}

function Radio<T extends string>({ name, value, current, label, onChange }: {
  name: string
  value: T
  current: T
  label: string
  onChange: (value: T) => void
}) {
  return (
    <label className="inline-flex items-center gap-2 mr-4">
      <input type="radio" name={name} value={value} checked={current === value} onChange={() => onChange(value)} />
      <span>{label}</span>
    </label>
  )
}

function Field({ label, placeholder, value, onChange, type = 'text', options, warning }: {
  label: string
  placeholder?: string
  value: string
  onChange: (value: string) => void
  type?: 'text' | 'number' | 'password'
  /** When given, the input becomes a combobox: a free-text field with these ids as a dropdown. */
  options?: readonly string[]
  /** A soft, inline advisory shown under the field (e.g. "this id won't work on the API"). */
  warning?: React.ReactNode
}) {
  const listId = useId()
  const hasOptions = Boolean(options && options.length > 0)
  return (
    <label className="block text-sm text-gray-300">
      <span className="block text-gray-400 mb-1">{label}</span>
      <input className="input w-full mono" type={type} placeholder={placeholder} value={value}
        list={hasOptions ? listId : undefined}
        onChange={(event) => onChange(event.target.value)} />
      {hasOptions && (
        <datalist id={listId}>
          {options!.map((id) => <option key={id} value={id} />)}
        </datalist>
      )}
      {warning && <p className="mt-1 text-xs text-yellow-400" role="status">{warning}</p>}
    </label>
  )
}

/**
 * The Anthropic API rejects the short aliases the Claude Code CLI accepts ("opus", "sonnet"): it
 * needs a full dated id like `claude-opus-5-5`. A bare alias here fails every call with a silent
 * 400 — so flag it before the operator loses a run to it. Every real Anthropic id starts with
 * "claude-"; anything else that is non-empty is almost certainly a mistaken alias.
 */
function anthropicModelWarning(model: string): string | null {
  const value = model.trim()
  if (!value || value.startsWith('claude-')) return null
  return 'Looks like a Claude Code CLI short name — the Anthropic API needs a full id such as claude-opus-5-5 or claude-sonnet-5-5.'
}

/**
 * The top-level `[llm] model` is a global override: when set, it wins over the provider's own
 * model for every agent. The UI only ever exposed it under the Claude Code CLI provider (as the
 * "Model" field), so a short name left over from CLI days — "opus" — stayed invisible after a
 * switch to an API provider while still poisoning every call with an id the API rejects.
 *
 * This surfaces it wherever it would take effect: on an API/Ollama provider, if a base override
 * is set, say what it is, that it overrides the field below, warn if it is a bare CLI alias on
 * Anthropic, and offer a one-click clear. Under claude-code-cli it stays hidden here, because the
 * CLI block's own "Model" field already shows and edits the same value.
 */
function BaseModelOverrideBanner({ provider, model, onClear }: {
  provider: LlmProvider
  model: string
  onClear: () => void
}) {
  if (provider === 'claude-code-cli' || !model.trim()) return null
  const warning = provider === 'anthropic-api' ? anthropicModelWarning(model) : null
  return (
    <div className="rounded border border-yellow-600 bg-yellow-900/20 p-3 text-sm space-y-2" role="status">
      <p className="text-yellow-200">
        A base model override is set — <code className="mono">{model.trim()}</code> — and it overrides this
        provider's model for every agent.
      </p>
      {warning && <p className="text-xs text-yellow-400">{warning}</p>}
      <button type="button" className="btn btn-sm" onClick={onClear}>
        Clear override (use the provider model below)
      </button>
    </div>
  )
}

export function LlmSettingsCard({ llm, knownModels }: {
  llm: LlmSettings
  knownModels: Record<string, string[]>
}) {
  const [form, setForm] = useState<Form>(() => fromApi(llm))
  const save = useSaveLlmSettings()
  const test = useTestLlm()
  const set = <K extends keyof Form>(key: K) => (value: Form[K]) => {
    test.reset()
    setForm((current) => ({ ...current, [key]: value }))
  }
  // When the operator focuses the api-key field (clicks or tabs in) and the current value is
  // the mask, clear it: typing after the mask would just extend "••••" with new characters.
  const clearKeyMaskOnFocus = <K extends keyof Form>(key: K) => () => {
    setForm((current) => (current[key] === MASK_VALUE ? { ...current, [key]: '' as Form[K] } : current))
  }
  const testResult = test.data
  const anthropicKeySet = llm.anthropic.api_key === MASK_VALUE
  const openaiKeySet = llm.openai.api_key === MASK_VALUE
  return (
    <Card title="LLM provider">
      {llm.restart_required && (
        <div className="mb-4 rounded border border-yellow-600 bg-yellow-900/30 p-3 text-sm text-yellow-300" role="status">
          Restart <code className="mono">argus serve</code> for these changes to take effect. The current session is
          still using the previous configuration.
        </div>
      )}
      <form className="space-y-5" onSubmit={(event) => {
        event.preventDefault()
        save.mutate(toBody(form), { onSuccess: (settings) => setForm(fromApi(settings.llm)) })
      }}>
        <fieldset className="space-y-2">
          <legend className="text-sm font-semibold text-gray-200 mb-1">Content provider</legend>
          <div className="text-sm text-gray-300">
            <Radio name="provider" value="claude-code-cli" current={form.provider} label="Claude Code CLI" onChange={set('provider')} />
            <Radio name="provider" value="ollama" current={form.provider} label="Ollama (local)" onChange={set('provider')} />
            <Radio name="provider" value="anthropic-api" current={form.provider} label="Anthropic API" onChange={set('provider')} />
            <Radio name="provider" value="openai-api" current={form.provider} label="OpenAI API" onChange={set('provider')} />
          </div>
          <p className="text-xs text-gray-400">Reads your documents: Analyst, Triage, Validator and summaries.</p>

          <BaseModelOverrideBanner provider={form.provider} model={form.model} onClear={() => set('model')('')} />

          {form.provider === 'ollama' && (
            <div className="space-y-3">
              <Field label="Base URL" placeholder="http://127.0.0.1:11434" value={form.baseUrl} onChange={set('baseUrl')} />
              <Field label="Model" placeholder="qwen2.5:32b-instruct" value={form.ollamaModel} onChange={set('ollamaModel')} />
              <Field label="Keep alive" placeholder="10m" value={form.keepAlive} onChange={set('keepAlive')} />
            </div>
          )}

          {form.provider === 'claude-code-cli' && (
            <div className="space-y-3">
              <Field label="Model" placeholder="opus" value={form.model} onChange={set('model')} />
              <Field label="claude binary" placeholder="claude" value={form.claudeBinary} onChange={set('claudeBinary')} />
            </div>
          )}

          {form.provider === 'anthropic-api' && (
            <div className="space-y-3">
              <label className="block text-sm text-gray-300">
                <span className="block text-gray-400 mb-1">
                  API key {anthropicKeySet && form.anthropicKey === MASK_VALUE && <span className="text-xs text-gray-500">(stored — type to replace)</span>}
                </span>
                <input className="input w-full mono" type="password" autoComplete="off"
                  placeholder="sk-ant-…" value={form.anthropicKey}
                  onChange={(event) => set('anthropicKey')(event.target.value)}
                  onFocus={clearKeyMaskOnFocus('anthropicKey')} />
              </label>
              <p className="text-xs text-gray-400">
                Preferred: set <code className="mono">ANTHROPIC_API_KEY</code> in the environment before{' '}
                <code className="mono">argus serve</code>. The env var always wins over this field.
              </p>
              <Field label="Model" placeholder="claude-sonnet-5-5" value={form.anthropicModel}
                onChange={set('anthropicModel')} options={knownModels['anthropic-api']}
                warning={anthropicModelWarning(form.anthropicModel)} />
              <Field label="Base URL" placeholder="https://api.anthropic.com" value={form.anthropicBaseUrl} onChange={set('anthropicBaseUrl')} />
              <Field label="anthropic-version" placeholder="2023-06-01" value={form.anthropicVersion} onChange={set('anthropicVersion')} />
            </div>
          )}

          {form.provider === 'openai-api' && (
            <div className="space-y-3">
              <label className="block text-sm text-gray-300">
                <span className="block text-gray-400 mb-1">
                  API key {openaiKeySet && form.openaiKey === MASK_VALUE && <span className="text-xs text-gray-500">(stored — type to replace)</span>}
                </span>
                <input className="input w-full mono" type="password" autoComplete="off"
                  placeholder="sk-…" value={form.openaiKey}
                  onChange={(event) => set('openaiKey')(event.target.value)}
                  onFocus={clearKeyMaskOnFocus('openaiKey')} />
              </label>
              <p className="text-xs text-gray-400">
                Preferred: set <code className="mono">OPENAI_API_KEY</code> in the environment before{' '}
                <code className="mono">argus serve</code>. The env var always wins over this field.
              </p>
              <Field label="Model" placeholder="gpt-4o" value={form.openaiModel}
                onChange={set('openaiModel')} options={knownModels['openai-api']} />
              <Field label="Base URL" placeholder="https://api.openai.com/v1" value={form.openaiBaseUrl} onChange={set('openaiBaseUrl')} />
              <Field label="Organization (optional)" placeholder="org_…" value={form.openaiOrganization} onChange={set('openaiOrganization')} />
            </div>
          )}

          <Field label="timeout_seconds" type="number" value={form.timeout} onChange={set('timeout')} />

          {form.provider !== 'claude-code-cli' && (
            <div className="space-y-2">
              <button type="button" className="btn btn-sm" disabled={test.isPending}
                onClick={() => {
                  if (form.provider === 'ollama') {
                    test.mutate({ provider: 'ollama', ollama: { base_url: form.baseUrl, model: form.ollamaModel } })
                  } else if (form.provider === 'anthropic-api') {
                    test.mutate({
                      provider: 'anthropic-api',
                      anthropic: {
                        api_key: form.anthropicKey, model: form.anthropicModel,
                        base_url: form.anthropicBaseUrl, anthropic_version: form.anthropicVersion,
                      },
                    })
                  } else if (form.provider === 'openai-api') {
                    test.mutate({
                      provider: 'openai-api',
                      openai: {
                        api_key: form.openaiKey, model: form.openaiModel,
                        base_url: form.openaiBaseUrl, organization: form.openaiOrganization,
                      },
                    })
                  }
                }}>
                Test connection
              </button>
              <div role="status" aria-live="polite" className="text-sm">
                {test.error && <p className="text-red-400">{test.error.message}</p>}
                {testResult && !testResult.ok && <p className="text-red-400">Connection failed: {testResult.error}</p>}
                {testResult?.ok && (
                  <div className="text-green-400">
                    <p>Connected. {testResult.models?.length ?? 0} models available.</p>
                    {testResult.model_present === true && form.provider === 'ollama' && (
                      <p>Model <span className="mono">{form.ollamaModel}</span> is installed.</p>
                    )}
                    {testResult.model_present === true && form.provider !== 'ollama' && (
                      <p>Model <span className="mono">
                        {form.provider === 'anthropic-api' ? form.anthropicModel : form.openaiModel}
                      </span> is available.</p>
                    )}
                    {testResult.model_present === false && form.provider === 'ollama' && (
                      <p className="text-yellow-400">
                        Model <span className="mono">{form.ollamaModel}</span> is not installed. Pull it with{' '}
                        <code className="mono">ollama pull {form.ollamaModel}</code>.
                      </p>
                    )}
                    {testResult.model_present === false && form.provider !== 'ollama' && (
                      <p className="text-yellow-400">
                        Model not listed on this account. The call may still work if the id is valid.
                      </p>
                    )}
                    {testResult.models && testResult.models.length > 0 && (
                      <p className="text-xs text-gray-400 mono break-words">{testResult.models.slice(0, 20).join(', ')}
                        {testResult.models.length > 20 && ` … (+${testResult.models.length - 20})`}
                      </p>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </fieldset>

        <PerAgentSection
          agents={form.agents}
          baseProvider={form.provider}
          knownModels={knownModels}
          onChange={(name, override) => setForm((current) => ({
            ...current, agents: { ...current.agents, [name]: override },
          }))}
        />

        <fieldset className="space-y-2">
          <legend className="text-sm font-semibold text-gray-200 mb-1">Search provider</legend>
          <div className="text-sm text-gray-300">
            <Radio name="search" value="claude-code-cli" current={form.search} label="Claude Code CLI" onChange={set('search')} />
            <Radio name="search" value="anthropic-api" current={form.search} label="Anthropic API (web_search)" onChange={set('search')} />
            <Radio name="search" value="disabled" current={form.search} label="Disabled (RSS + ingest only)" onChange={set('search')} />
          </div>
          <p className="text-xs text-gray-400">
            Runs the Collector's public web searches. Claude Code CLI uses its agentic WebSearch tool;
            Anthropic API uses the server-side web_search tool (needs the Anthropic key, billed at
            $10 / 1000 searches). Ollama and OpenAI-compatible providers have no search and mean "disabled".
          </p>
        </fieldset>

        {save.error && <p className="text-sm text-red-400" role="alert">{save.error.message}</p>}
        <div className="flex gap-2">
          <button type="submit" className="btn btn-primary btn-sm" disabled={save.isPending}>Save</button>
          <button type="button" className="btn btn-sm" disabled={save.isPending}
            onClick={() => { save.reset(); test.reset(); setForm(fromApi(llm)) }}>
            Discard
          </button>
        </div>
      </form>
      <p className="text-xs text-gray-400 mt-4">
        Limits and scoring are edited in <code className="mono">argus.toml</code>.
      </p>
    </Card>
  )
}


function PerAgentSection({
  agents, baseProvider, knownModels, onChange,
}: {
  agents: AgentsSettings
  baseProvider: LlmProvider
  knownModels: Record<string, string[]>
  onChange: (name: AgentName, override: { provider: string; model: string }) => void
}) {
  const anyOverride = UI_AGENTS.some((a) => agents[a.name].provider || agents[a.name].model)
  // Keep the section collapsed by default when every slot is "use base": a first-time operator
  // sees a tidy card without a tangled per-agent matrix. Expand automatically when something
  // IS overridden so a returning operator does not forget it is on.
  return (
    <details open={anyOverride} className="group border border-gray-700 rounded">
      <summary className="cursor-pointer select-none px-3 py-2 text-sm text-gray-300 hover:text-gray-100">
        <span className="font-semibold text-gray-200">Per-agent model overrides</span>
        <span className="text-gray-500 text-xs ml-2">
          {anyOverride ? '(some overrides active)' : '(optional — use the base provider everywhere)'}
        </span>
      </summary>
      <div className="px-3 pb-3 pt-1 space-y-3">
        <p className="text-xs text-gray-400">
          Pick a cheap provider+model for the yes/no agents and a strong one for extraction. Any
          agent set to <em>Use base provider</em> inherits what you picked above. These map to{' '}
          <code className="mono">[llm.agents.*]</code> in <code className="mono">argus.toml</code>.
        </p>
        {UI_AGENTS.map(({ name, label, hint }) => (
          <AgentRow key={name} name={name} label={label} hint={hint}
            override={agents[name]} baseProvider={baseProvider} knownModels={knownModels}
            onChange={(ov) => onChange(name, ov)} />
        ))}
      </div>
    </details>
  )
}


function AgentRow({
  name, label, hint, override, baseProvider, knownModels, onChange,
}: {
  name: AgentName
  label: string
  hint: string
  override: { provider: string; model: string }
  baseProvider: LlmProvider
  knownModels: Record<string, string[]>
  onChange: (override: { provider: string; model: string }) => void
}) {
  const effectiveProvider = override.provider || baseProvider
  const listId = useId()
  const options = knownModels[effectiveProvider] ?? []
  const warning = effectiveProvider === 'anthropic-api' ? anthropicModelWarning(override.model) : null
  return (
    <div className="grid grid-cols-1 md:grid-cols-[8rem_minmax(0,1fr)_minmax(0,1fr)] gap-2 items-start">
      <div className="pt-1">
        <p className="text-sm text-gray-200">{label}</p>
        <p className="text-xs text-gray-500 leading-tight">{hint}</p>
      </div>
      <label className="block text-sm text-gray-300">
        <span className="block text-gray-400 mb-1 text-xs">Provider</span>
        <select
          aria-label={`${label} provider`}
          className="input w-full"
          value={override.provider}
          onChange={(event) => onChange({ ...override, provider: event.target.value })}
        >
          <option value="">Use base provider ({PROVIDER_LABELS[baseProvider] ?? baseProvider})</option>
          <option value="claude-code-cli">Claude Code CLI</option>
          <option value="ollama">Ollama (local)</option>
          <option value="anthropic-api">Anthropic API</option>
          <option value="openai-api">OpenAI API</option>
        </select>
      </label>
      <label className="block text-sm text-gray-300">
        <span className="block text-gray-400 mb-1 text-xs">Model (optional)</span>
        <input
          aria-label={`${label} model`}
          className="input w-full mono"
          type="text"
          list={options.length > 0 ? listId : undefined}
          placeholder={_modelPlaceholder(effectiveProvider, name)}
          value={override.model}
          onChange={(event) => onChange({ ...override, model: event.target.value })}
        />
        {options.length > 0 && (
          <datalist id={listId}>
            {options.map((id) => <option key={id} value={id} />)}
          </datalist>
        )}
        {warning && <p className="mt-1 text-xs text-yellow-400" role="status">{warning}</p>}
      </label>
    </div>
  )
}


function _modelPlaceholder(provider: string, agent: AgentName): string {
  // Nudges toward sensible per-agent models for cost / quality balance. Operator can override.
  if (provider === 'openai-api') return agent === 'triage' ? 'gpt-4o-mini' : 'gpt-4o'
  if (provider === 'anthropic-api') return agent === 'triage' ? 'claude-haiku-4-5-20251001' : 'claude-sonnet-5-5'
  if (provider === 'ollama') return 'qwen2.5:32b-instruct'
  if (provider === 'claude-code-cli') return agent === 'triage' ? 'haiku' : 'sonnet'
  return 'leave empty to use base'
}
