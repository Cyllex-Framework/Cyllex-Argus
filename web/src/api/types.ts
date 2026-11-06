export type AssessmentStatus = 'corroborated' | 'single-source' | 'contested'
export type JobState = 'queued' | 'running' | 'finished' | 'paused' | 'failed'

export interface EntityRef {
  id: string
  stix_type: string
  name: string
  external_id: string | null
  attack: boolean
  label: string
  attributes?: Record<string, string>
}

export interface Citation {
  claim_id: number
  quote: string
  quote_status: string
  polarity: 'asserts' | 'refutes'
  document_title: string
  location: string | null
  publisher: string
  published_at: string | null
}

export type AnalyticConfidenceLevel = 'high' | 'moderate' | 'low'

export interface Fact {
  subject: EntityRef
  predicate: string
  object: EntityRef
  status: AssessmentStatus
  confidence: number
  admiralty: string
  first_seen: string | null
  last_seen: string | null
  citations: Citation[]
  source_count: number
  assessment_id?: number | null
  analytic_confidence?: AnalyticConfidenceLevel | null
  confidence_rationale?: string | null
}

export type Freshness = 'active' | 'dormant' | 'historical' | 'unknown'

export type EntityDetail =
  | { kind: string; value: string; freshness: Freshness; last_seen: string | null }
  | { sector_hint: string | null }
  | { cve_id: string }

export interface ThreatProfile {
  entity: EntityRef
  detail?: EntityDetail
  aliases: { alias: string; origin: string }[]
  facts: Fact[]
  attack_matrix?: { tactics: Tactic[] }
}

export interface ThreatSummary {
  id: string
  stix_type: string
  name: string
  external_id: string | null
  label: string
  facts: number
  attack: boolean
}

export interface GraphNode {
  id: string
  label: string
  type: string
  attack: boolean
  /** Only indicator nodes carry it. */
  freshness?: Freshness
  /** First MITRE tactic when the node is an attack-pattern and the ATT&CK catalog is loaded. */
  tactic?: string
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  predicate: string
  status: AssessmentStatus
  confidence: number
}

export interface Graph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  /** True when the server capped the payload at `limit` nodes. */
  truncated?: boolean
}

export interface Campaign {
  id: string
  name: string
  external_id: string | null
  label: string
  first_seen: string | null
  last_seen: string | null
  /** How many distinct attack-patterns this campaign is linked to via `uses` assessments. */
  techniques: number
}

export interface CampaignsResponse {
  campaigns: Campaign[]
  scope: string
}

export type FactStatus = AssessmentStatus

export interface MatrixTechnique {
  id: string
  external_id: string
  name: string
  status: FactStatus
  confidence: number
  admiralty: string
  sources: number
}

export interface Tactic {
  id: string
  name: string
  techniques: MatrixTechnique[]
}

export interface TechniqueDetail {
  external_id: string
  name: string
  tactics: { id: string; name: string }[]
  is_subtechnique: boolean
  description: string
  platforms: string[]
  detection: string
  data_sources: string[]
  permissions_required: string[]
}

export interface CatalogTechnique {
  id: string
  external_id: string
  name: string
  tactics: string[]
}

export interface AttackCatalog {
  tactics: { id: string; name: string; techniques: CatalogTechnique[] }[]
}

export interface TokenUsageTotal {
  calls: number
  input_tokens: number
  output_tokens: number
  total_tokens: number
  cost_usd: number
}

export interface TokenUsage {
  by_stage: Record<string, TokenUsageTotal>
  total: TokenUsageTotal
}

export interface InvestigationSummary {
  id: number
  target: string
  state: string
  resolved_entity_id: string | null
  started_at: string
  finished_at: string | null
  collected: boolean
  /** Username that started the run, or "system" for a scheduler/CLI run. Optional so existing
   *  fixtures keep compiling. */
  started_by?: string
  stage_counts: Record<string, number>
  /** Total LLM tokens and cost across every pipeline stage of this investigation. */
  token_usage: TokenUsageTotal
  /** Human-readable "why" when state is "paused" and the pause was NOT operator-initiated
   *  (e.g. "Server restart interrupted this run."). Null for operator-paused and non-paused
   *  rows; the UI uses it to render an amber banner above the resume affordance so the
   *  operator knows what happened without having to read the server log. Optional at the
   *  TypeScript level so existing fixture builders keep compiling — the SPA treats missing
   *  and null the same (`!!paused_reason`). */
  paused_reason?: string | null
}

export interface Overview {
  counts: {
    threats: number
    documents: Record<string, number>
    assessments: Record<string, number>
    investigations: number
  }
  recent_investigations: InvestigationSummary[]
  unrated_publishers: { id: number; name: string }[]
}

export interface DocumentSummary {
  id: number
  title: string
  publisher: string
  stage: string
  published_at: string | null
  retrieved_at: string
  failure_reason: string | null
  location: string | null
}

export interface DocumentClaim {
  id: number
  subject: string
  predicate: string
  object: string
  quote: string
  quote_status: string
  polarity: string
  span: [number, number] | null
}

export interface DocumentDetail extends DocumentSummary {
  text: string
  claims: DocumentClaim[]
}

export interface InvestigationDetail extends InvestigationSummary {
  documents: DocumentSummary[]
  failures: { title: string; reason: string }[]
}

export interface Source {
  id: number
  name: string
  domain: string | null
  reliability: string
  documents: number
  tlp?: Tlp | null
  /** Other bylines this row has published under. The row is the unit of independence, so these
   *  are what an operator rating it is actually rating. Optional so fixtures keep compiling. */
  also_known_as?: string[]
}

/** One publisher Argus ships a grade for, with the reason the operator is asked to accept. */
export interface SourceProposal {
  id: number
  name: string
  current: string
  proposed: string
  rationale: string
  organisation: string
  overrides_analyst: boolean
}

export interface GradeableSources {
  proposals: SourceProposal[]
  /** Proposals that would replace a grade a human already set. Never applied automatically. */
  would_override: SourceProposal[]
  unjudged: number
  /** Unjudged publishers the shipped table cannot speak to — F is accurate for those. */
  unrecognised: number
  publishers: number
}

export interface DuplicateSourceRow {
  id: number
  name: string
  documents: number
}

/** Several publisher rows that are one organisation. `keep` absorbs `drop`. */
export interface DuplicateSourceGroup {
  org_key: string
  keep: DuplicateSourceRow
  drop: DuplicateSourceRow[]
}

export interface DuplicateSources {
  groups: DuplicateSourceGroup[]
  rows: number
}

/** The saved publisher, and the queued `recompute` job that rescores the assessments with its new reliability. */
export interface SourceUpdate {
  id: number
  name: string
  domain: string | null
  reliability: string
  job: Job
}

export interface Settings {
  attack: { present: boolean; techniques: number; groups: number; software: number }
  claude: { found: boolean }
  config: Record<string, unknown>
  home: string
  llm: LlmSettings
  /** Priced model ids per direct-API provider, for the Settings model picker. May be absent
   *  on an older server; treat a missing key as an empty list. */
  known_models?: Record<string, string[]>
}

export type LlmProvider = 'claude-code-cli' | 'ollama' | 'anthropic-api' | 'openai-api'
export type SearchProvider = 'claude-code-cli' | 'anthropic-api' | 'disabled'

export interface OllamaSettings {
  base_url: string
  model: string
  keep_alive: string
}

/** Masked view of the Anthropic API provider config. `api_key` is '' when unset,
 *  '••••••••' when the server holds a value. The UI shows the mask and only sends plaintext
 *  back when the operator explicitly re-types the key. */
export interface AnthropicSettings {
  api_key: string
  model: string
  base_url: string
  anthropic_version: string
}

export interface OpenAISettings {
  api_key: string
  model: string
  base_url: string
  organization: string
}

/** Per-agent override. Both fields optional: empty strings = inherit the base [llm] provider /
 *  model. `provider` is '' or one of LlmProvider; the server validates. */
export interface AgentOverride {
  provider: string
  model: string
}

export interface AgentsSettings {
  triage: AgentOverride
  analyst: AgentOverride
  summary: AgentOverride
}

/** What GET /api/settings reports: the LLM config stored in argus.toml. */
export interface LlmSettings {
  provider: LlmProvider
  model: string | null
  timeout_seconds: number
  claude_binary: string
  ollama: OllamaSettings
  anthropic: AnthropicSettings
  openai: OpenAISettings
  agents: AgentsSettings
  search_provider: SearchProvider
  /** True when argus.toml's LLM blocks differ from the config this `argus serve` process started with. */
  restart_required: boolean
}

/** Body of PUT /api/settings/llm. */
export interface LlmUpdate {
  provider: LlmProvider
  model: string | null
  timeout_seconds: number
  claude_binary: string
  ollama: OllamaSettings
  /** Optional: when the operator did not touch the key field, send the mask back and the server preserves the stored value. */
  anthropic?: AnthropicSettings
  openai?: OpenAISettings
  agents?: AgentsSettings
  search: { provider: SearchProvider }
}

export interface LlmTestRequest {
  provider: LlmProvider
  claude_binary?: string
  ollama?: { base_url: string; model: string }
  anthropic?: AnthropicSettings
  openai?: OpenAISettings
}

export type LlmTestResult =
  | { ok: true; models?: string[]; model_present?: boolean; binary_path?: string }
  | { ok: false; error: string }

export interface Job {
  id: string
  kind: 'investigate' | 'resume' | 'ingest' | 'attack_update' | 'recompute'
    | 'retry_document' | 'supply_document'
  params: Record<string, unknown>
  state: JobState
  created_at: string
  started_at: string | null
  finished_at: string | null
  message: string | null
  result: Record<string, unknown> | null
  events: number
}

export interface LogJob {
  id: string
  kind: Job['kind']
  state: JobState
  started_at: string | null
  finished_at: string | null
  message: string | null
  duration_ms: number | null
  events_count: number
}

export interface LogEvent {
  id: number
  investigation_id: number
  investigation_target: string
  document_id: number | null
  document_title: string | null
  stage: string
  decision: string
  reason: string | null
  created_at: string
  duration_ms: number | null
  input_tokens: number | null
  output_tokens: number | null
  cost_usd: number | null
}

export interface LogsResponse {
  jobs: LogJob[]
  events: LogEvent[]
}

export interface LogsFilter {
  kind?: Job['kind'] | ''
  state?: JobState | ''
  since?: string
}

export interface JobEvent {
  seq: number
  time: string
  message: string
}

export type JobRequest =
  | { kind: 'investigate'; target: string; max_docs?: number; concurrency?: number }
  | { kind: 'resume'; investigation_id: number; concurrency?: number }
  | { kind: 'attack_update' }

export interface DashboardInvestigation {
  id: number
  target: string
  state: 'running' | 'finished' | 'failed' | string
  started_at: string
  finished_at: string | null
  failure_reason: string | null
  counts: Record<string, number>
  /** LLM tokens and cost spent on this investigation, broken down by pipeline stage. */
  token_usage: TokenUsage
  /** See InvestigationSummary.paused_reason. Optional so fixtures keep compiling. */
  paused_reason?: string | null
}

export interface DashboardEntity {
  id: string
  stix_type: string
  name: string
  external_id: string | null
  attack: boolean
  aliases: { alias: string; origin: string }[]
}

export interface InvestigationDashboard {
  investigation: DashboardInvestigation
  entity: DashboardEntity | null
  attack_matrix: { tactics: Tactic[] }
}

export interface TraceUsage {
  input_tokens: number
  output_tokens: number
  model: string | null
  duration_ms: number
}

export interface PipelineEvent {
  id: number
  document_id: number | null
  /** collector | triage | analyst | validator, plus `pipeline` for unexpected-exception events. */
  stage: string
  decision: string
  reason: string | null
  created_at: string
  duration_ms: number | null
  usage: TraceUsage | null
  has_raw: boolean
}

export interface TraceCost {
  input_tokens: number
  output_tokens: number
  usd: number
  duration_ms: number
}

export interface TraceDocument {
  id: number
  title: string
}

export interface TraceSummary {
  cost: TraceCost | null
  /** Titles of the documents the events refer to. */
  documents?: TraceDocument[]
  events: PipelineEvent[]
}

export interface TraceRaw {
  prompt: string
  response: string
}

/** Which claims a dashboard shows: everything known, or only what the investigation contributed. */
export type Scope = 'everything' | 'investigation'
/** The wire form of a non-default scope (`scope=investigation:<id>`); undefined means everything. */
export type ScopeParam = `investigation:${number | string}`

export type StixObservableType =
  | 'domain-name' | 'ipv4-addr' | 'ipv6-addr' | 'url' | 'file-hash' | 'vulnerability'

export interface Enricher {
  name: string
  description: string
  /** One-sentence statement of exactly what leaves the machine when this enricher runs. */
  outbound: string
  supported_types: StixObservableType[]
  enabled: boolean
  /** True for key-gated enrichers (VirusTotal today). UI shows an API-key input only when true. */
  requires_api_key: boolean
  /** Whether a key is stored on disk. Plaintext never crosses the API — this is the signal. */
  api_key_configured: boolean
  /** Masked placeholder "••••••••" when a key is stored, empty string otherwise. */
  api_key: string
  /** Name of an env var the operator can set so the key never touches argus.toml. */
  env_api_key: string
}

export interface MispServer {
  name: string
  url: string
  api_key: string
  env_api_key: string
  timestamp_days: number | null
  enabled: boolean
}

export interface TaxiiServer {
  name: string
  url: string
  collection: string
  api_key: string
  env_api_key: string
  username: string
  password: string
  added_after_days: number | null
  enabled: boolean
}

export interface Webhook {
  url: string
  secret: string
  env_secret: string
  on_states: string[]        // subset of {"finished", "paused"}; [] = both
  enabled: boolean
}

export interface SourceTestResult {
  ok: boolean
  error?: string
  events_sampled?: number    // MISP
  objects_sampled?: number   // TAXII
  status?: string            // Webhook: "sent" | "failed" | "skipped"
  detail?: string            // Webhook: HTTP status / error summary
}

export interface EnrichmentFinding {
  source: string
  key: string
  value: string
  observed_at: string | null
  detail: string | null
}

export interface EnrichmentResult {
  name: string
  indicator: string
  indicator_type: StixObservableType
  duration_ms: number
  error: string | null
  findings: EnrichmentFinding[]
}

export type Tlp = 'clear' | 'green' | 'amber' | 'amber-strict' | 'red'

export interface IdentityAttributes {
  sector?: string
  country?: string
}

export interface ActorTargetsRow {
  entity_id: string
  canonical_name: string
  stix_type: string
  assessment_count: number
  // 0.14+: surfaces how the actor matched. `sectors` is a direct hit on
  // actor.attributes.sectors (the STIX 2.1-correct 0.13 shape). `targets-identity`
  // is the historical path (actor has a `targets` claim against an identity whose
  // attribute matches). The UI shows a chip and ranks direct hits above indirect.
  source?: 'sectors' | 'targets-identity'
}

export interface StixImportReport {
  bundle_id: string | null
  entities_added: number
  entities_matched: number
  aliases_added: number
  claims_added: number
  identities_tagged: number
  skipped: string[]
}

/** The cached executive summary of a threat (GET/POST /api/threats/{id}/summary).
 *  `summary === null` means none was ever written; `stale` means the knowledge moved
 *  since it was (the prose stays readable — an old answer beats a blank card). */
export interface ExecutiveSummary {
  summary: string | null
  generated_at: string | null
  stale: boolean
  fact_count: number
  written_from_fact_count: number | null
  prompt_version: string | null
  model: string | null
  can_generate: boolean
}
