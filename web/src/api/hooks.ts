import { useEffect, useRef, useState } from 'react'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, apiFetch, deleteJson, postJson, putJson, queryString } from './client'
import type {
  AssessmentStatus,
  ActorTargetsRow, AttackCatalog, CampaignsResponse, DocumentDetail, DocumentSummary, DuplicateSources, Enricher, EnrichmentResult, ExecutiveSummary, GradeableSources, Graph, IdentityAttributes, InvestigationDashboard, InvestigationDetail, InvestigationSummary, Job, JobRequest, LlmTestRequest, LlmTestResult, LlmUpdate, LogsFilter, LogsResponse, MispServer, Overview,
  ScopeParam, Settings, Source, SourceTestResult, SourceUpdate, StixImportReport, StixObservableType, Tactic, TaxiiServer, TechniqueDetail, ThreatProfile, ThreatSummary, Tlp, TraceRaw, TraceSummary, Webhook,
} from './types'

export const isActiveJob = (job: Job) => job.state === 'queued' || job.state === 'running'

export type Role = 'reader' | 'operator' | 'admin'
export interface CurrentUser { username: string; role: Role }

const ROLE_RANK: Record<Role, number> = { reader: 0, operator: 1, admin: 2 }

/** True when `role` is at least `min` in the reader < operator < admin order. */
export function roleAtLeast(role: Role | undefined, min: Role): boolean {
  return role !== undefined && ROLE_RANK[role] >= ROLE_RANK[min]
}

/** The signed-in user and role, from /api/auth/me. Cached for the session. */
export function useCurrentUser() {
  return useQuery({
    queryKey: ['current-user'],
    queryFn: () => apiFetch<CurrentUser>('/api/auth/me'),
    staleTime: Infinity,
  })
}

/** True when the current user may perform write actions (operator or admin). */
export function useCanWrite(): boolean {
  return roleAtLeast(useCurrentUser().data?.role, 'operator')
}

/** True when the current user may manage users (admin). */
export function useCanAdmin(): boolean {
  return roleAtLeast(useCurrentUser().data?.role, 'admin')
}

/** True only when the user is *confirmed* a reader. Undefined-while-loading reads as false, so
 * write controls stay visible during the /auth/me round-trip and only hide for a known reader. */
export function useIsReader(): boolean {
  return useCurrentUser().data?.role === 'reader'
}

export interface ManagedUser {
  id: number
  username: string
  role: Role
  disabled: boolean
  created_at: string
  created_by: number | null
}

export function useUsers() {
  return useQuery({
    queryKey: ['users'],
    queryFn: () => apiFetch<{ users: ManagedUser[] }>('/api/users').then((r) => r.users),
  })
}

export function useUserMutations() {
  const client = useQueryClient()
  const invalidate = () => client.invalidateQueries({ queryKey: ['users'] })
  const create = useMutation({
    mutationFn: (body: { username: string; password: string; role: Role }) => postJson('/api/users', body),
    onSuccess: invalidate,
  })
  const update = useMutation({
    mutationFn: ({ id, ...body }: { id: number; role?: Role; disabled?: boolean }) => putJson(`/api/users/${id}`, body),
    onSuccess: invalidate,
  })
  const remove = useMutation({
    mutationFn: (id: number) => deleteJson(`/api/users/${id}`),
    onSuccess: invalidate,
  })
  const resetPassword = useMutation({
    mutationFn: ({ id, password }: { id: number; password: string }) => postJson(`/api/users/${id}/password`, { password }),
    onSuccess: invalidate,
  })
  return { create, update, remove, resetPassword }
}

// -- watchers ---------------------------------------------------------------------------------

export type ChangeKind = 'new' | 'new_source' | 'verified' | 'weakened' | 'contested'

export interface Watcher {
  id: number
  target: string
  entity_id: string | null
  cron_expr: string
  enabled: boolean
  created_by: number | null
  max_docs: number | null
  concurrency: number
  last_run_at: string | null
  next_run_at: string
  created_at: string
  unseen_count: number
}

export interface WatcherChangeCitation {
  quote: string
  publisher: string
  document_title: string
  location: string | null
  published_at: string | null
}

export interface WatcherChange {
  id: number
  watcher_id: number
  target: string | null
  entity_id: string | null
  kind: ChangeKind
  subject: string | null
  predicate: string | null
  object: string | null
  from_status: AssessmentStatus | null
  to_status: AssessmentStatus | null
  citation: WatcherChangeCitation | null
  detected_at: string
  run_job_id: string | null
}

export function useWatchers() {
  return useQuery({ queryKey: ['watchers'], queryFn: () => apiFetch<Watcher[]>('/api/watchers') })
}

export function useWatcherChanges(filter: { watcher_id?: number; before_id?: number; limit?: number } = {}) {
  return useQuery({
    queryKey: ['watcher-changes', filter],
    queryFn: () => apiFetch<WatcherChange[]>(`/api/watchers/changes${queryString(filter)}`),
  })
}

export function useWatcherMutations() {
  const client = useQueryClient()
  const invalidate = () => {
    client.invalidateQueries({ queryKey: ['watchers'] })
    client.invalidateQueries({ queryKey: ['watcher-changes'] })
  }
  const create = useMutation({
    mutationFn: (body: { target: string; cron_expr?: string; max_docs?: number; concurrency?: number }) =>
      postJson('/api/watchers', body),
    onSuccess: invalidate,
  })
  const setEnabled = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => putJson(`/api/watchers/${id}/enabled`, { enabled }),
    onSuccess: invalidate,
  })
  const remove = useMutation({
    mutationFn: (id: number) => deleteJson(`/api/watchers/${id}`),
    onSuccess: invalidate,
  })
  const runNow = useMutation({
    mutationFn: (id: number) => postJson<{ job_id: string }>(`/api/watchers/${id}/run-now`, {}),
    onSuccess: invalidate,
  })
  return { create, setEnabled, remove, runNow }
}

export function useMarkWatcherSeen() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, last_change_id }: { id: number; last_change_id: number }) =>
      postJson(`/api/watchers/${id}/seen`, { last_change_id }),
    onSuccess: () => client.invalidateQueries({ queryKey: ['watchers'] }),
  })
}

export function jobLabel(job: Job): string {
  switch (job.kind) {
    case 'investigate':
      return `Investigating ${String(job.params.target ?? '')}`
    case 'resume':
      return `Resuming investigation #${String(job.params.investigation_id ?? '')}`
    case 'ingest':
      return `Ingesting ${Array.isArray(job.params.files) ? job.params.files.length : 0} file(s)`
    case 'attack_update':
      return 'Updating ATT&CK'
    case 'recompute':
      return 'Recomputing confidences'
    // Both single-document jobs name the document, because that is what the operator was
    // looking at when they started it.
    case 'retry_document':
      return `Retrying document #${String(job.params.document_id ?? '')}`
    case 'supply_document':
      return `Analysing your file for document #${String(job.params.document_id ?? '')}`
  }
}

/** The page that shows a job's live progress, for the header's running-job link. */
export function jobPage(job: Job): string {
  switch (job.kind) {
    case 'investigate':
      return typeof job.params.investigation_id === 'number' || typeof job.params.investigation_id === 'string'
        ? `/investigations/${encodeURIComponent(String(job.params.investigation_id))}/dashboard`
        : '/investigations'
    case 'resume':
      return `/investigations/${encodeURIComponent(String(job.params.investigation_id ?? ''))}/dashboard`
    case 'ingest':
      return '/documents'
    case 'attack_update':
      return '/settings'
    case 'recompute':
      return '/sources'
    case 'retry_document':
    case 'supply_document':
      return typeof job.params.document_id === 'number' || typeof job.params.document_id === 'string'
        ? `/documents/${encodeURIComponent(String(job.params.document_id))}`
        : '/documents'
  }
}

export interface JobPick {
  /** A job this page started itself; the job list may not know it until its next refetch. */
  started?: string | null
  /** Narrows the jobs of the given kinds further, e.g. to one investigation. */
  matches?: (job: Job) => boolean
  /** With nothing active or started, fall back to the most recent job, so its result stays on screen. */
  latest?: boolean
}

/**
 * Choose the job a page follows from the server's job list (newest first): the job it just started while that is
 * active, else the running job of the kinds, else the oldest queued one, else the job it started, else the latest.
 * Deriving it from the server, not component state, keeps the progress on screen across navigations and reloads.
 */
export function pickJob(jobs: Job[] | undefined, kinds: readonly Job['kind'][], { started = null, matches, latest = true }: JobPick = {}): string | null {
  const relevant = (jobs ?? []).filter((job) => kinds.includes(job.kind) && (!matches || matches(job)))
  const mine = started ? relevant.find((job) => job.id === started) : undefined
  if (started && (!mine || isActiveJob(mine))) return started
  const active = relevant.find((job) => job.state === 'running') ?? relevant.findLast(isActiveJob)
  if (active) return active.id
  if (started) return started
  return latest ? (relevant[0]?.id ?? null) : null
}

export function useActiveJob(kinds: readonly Job['kind'][], pick: JobPick = {}): string | null {
  const { data: jobs } = useJobs()
  return pickJob(jobs, kinds, pick)
}

/**
 * Refresh every query when a job that was active is no longer: a job that ends while no progress panel follows it
 * (on the dashboard, say) must not leave pages showing what the database held before it ran. Mount it wherever an on-job-end refresh matters;
 * extra mounts are idempotent (React Query dedupes concurrent invalidations).
 */
export function useRefreshWhenJobsEnd() {
  const { data: jobs } = useJobs()
  const client = useQueryClient()
  const active = useRef<Set<string>>(new Set())
  useEffect(() => {
    if (!jobs) return
    const now = new Set(jobs.filter(isActiveJob).map((job) => job.id))
    const ended = [...active.current].some((id) => !now.has(id))
    active.current = now
    if (ended) void client.invalidateQueries()
  }, [jobs, client])
}

export const useOverview = () =>
  useQuery({ queryKey: ['overview'], queryFn: () => apiFetch<Overview>('/api/overview') })

/** The full Enterprise ATT&CK structure; it changes only when the ATT&CK file is updated, so it stays fresh for 10 minutes. */
export const useAttackCatalog = () =>
  useQuery({
    queryKey: ['attack-catalog'],
    queryFn: () => apiFetch<AttackCatalog>('/api/attack/catalog'),
    staleTime: 10 * 60 * 1000,
    retry: false, // a 404 means ATT&CK is not loaded; the matrix falls back to observed techniques
  })

export const useThreats = (params: { q: string; type: string; catalog: boolean }) =>
  useQuery({
    queryKey: ['threats', params],
    queryFn: () => apiFetch<ThreatSummary[]>(`/api/threats${queryString(params)}`),
    placeholderData: keepPreviousData, // keep the last results on screen while the next search loads
  })

/** A null id disables the query (used by panels that open on demand). */
export const useThreat = (id: string | null, scope?: ScopeParam) =>
  useQuery({
    queryKey: ['threat', id, scope ?? null],
    queryFn: () => apiFetch<ThreatProfile>(`/api/threats/${encodeURIComponent(id ?? '')}${queryString({ scope })}`),
    enabled: id !== null,
  })

const summaryPath = (id: string) => `/api/threats/${encodeURIComponent(id)}/summary`

/** The cached executive summary. Reading never calls the LLM, so this is safe on every
 *  page load; writing one is `useWriteThreatSummary`. */
export const useThreatSummary = (id: string | null) =>
  useQuery({
    queryKey: ['threat-summary', id],
    queryFn: () => apiFetch<ExecutiveSummary>(summaryPath(id ?? '')),
    enabled: id !== null,
  })

/** Write (or rewrite) the executive summary. Costs one LLM call, so it is only ever fired
 *  by an explicit operator action — the pipeline writes its own at the end of a run. */
export function useWriteThreatSummary(id: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: () => postJson<ExecutiveSummary>(summaryPath(id), {}),
    onSuccess: (fresh) => {
      client.setQueryData(['threat-summary', id], fresh)
    },
  })
}

export const useGraph = (id: string, depth: 1 | 2 | 3, limit?: number, scope?: ScopeParam) =>
  useQuery({
    queryKey: ['graph', id, depth, limit ?? null, scope ?? null],
    queryFn: () => apiFetch<Graph>(`/api/threats/${encodeURIComponent(id)}/graph${queryString({ depth, limit, scope })}`),
  })

export const useCampaigns = (id: string | null, scope?: ScopeParam) =>
  useQuery({
    queryKey: ['campaigns', id, scope ?? null],
    queryFn: () => apiFetch<CampaignsResponse>(`/api/threats/${encodeURIComponent(id ?? '')}/campaigns${queryString({ scope })}`),
    enabled: id !== null,
  })

export const useCampaignMatrix = (campaignId: string | null) =>
  useQuery({
    queryKey: ['campaign-matrix', campaignId],
    queryFn: () => apiFetch<{ tactics: Tactic[] }>(`/api/campaigns/${encodeURIComponent(campaignId ?? '')}/matrix`),
    enabled: campaignId !== null,
  })

export const useTechniqueDetail = (externalId: string | null) =>
  useQuery({
    queryKey: ['technique-detail', externalId],
    queryFn: () => apiFetch<TechniqueDetail>(`/api/attack/technique/${encodeURIComponent(externalId ?? '')}`),
    enabled: externalId !== null && externalId !== '',
    staleTime: 60 * 60 * 1000, // the catalog is cached server-side; the client can hold it longer too
  })

export const useDocuments = (params: { stage: string; q: string }) =>
  useQuery({
    queryKey: ['documents', params],
    queryFn: () => apiFetch<DocumentSummary[]>(`/api/documents${queryString(params)}`),
    placeholderData: keepPreviousData, // keep the last rows on screen while the next filter or search loads
  })

export const useDocument = (id: string) =>
  useQuery({ queryKey: ['document', id], queryFn: () => apiFetch<DocumentDetail>(`/api/documents/${encodeURIComponent(id)}`) })

export const useInvestigations = () => {
  const { data: jobs } = useJobs()
  const jobActive = jobs?.some((job) => (job.kind === 'investigate' || job.kind === 'resume') && isActiveJob(job)) ?? false
  return useQuery({
    queryKey: ['investigations'],
    queryFn: () => apiFetch<InvestigationSummary[]>('/api/investigations'),
    // While an investigation is being worked on, poll so the list shows it (and its state and
    // document counts) without a manual refresh. jobActive covers the moment before the row
    // exists (job queued or running); the data check keeps polling until the row reaches a
    // terminal state, then stops.
    refetchInterval: (query) =>
      jobActive || query.state.data?.some((inv) => inv.state === 'running' || inv.state === 'queued')
        ? 2500
        : false,
  })
}

export const useInvestigation = (id: string) =>
  useQuery({
    queryKey: ['investigation', id],
    queryFn: () => apiFetch<InvestigationDetail>(`/api/investigations/${encodeURIComponent(id)}`),
  })

export const useInvestigationDashboard = (id: string, scope?: ScopeParam) =>
  useQuery({
    queryKey: ['investigation-dashboard', id, scope ?? null],
    queryFn: () => apiFetch<InvestigationDashboard>(`/api/investigations/${encodeURIComponent(id)}/dashboard${queryString({ scope })}`),
    placeholderData: keepPreviousData, // keep the page (and the scope switch) on screen while the other scope loads
  })

const tracePath = (id: string) => `/api/investigations/${encodeURIComponent(id)}/trace`

export const useTrace = (id: string) =>
  useQuery({ queryKey: ['trace', id], queryFn: () => apiFetch<TraceSummary>(tracePath(id)) })

/** The raw prompt and response of one event; `enabled` keeps it from loading until the user asks. */
export const useTraceRaw = (id: string, eventId: number, enabled: boolean) =>
  useQuery({
    queryKey: ['trace-raw', id, eventId],
    queryFn: () => apiFetch<TraceRaw>(`${tracePath(id)}/${eventId}/raw`),
    enabled,
    retry: false,
  })

export function useDeleteTrace(id: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: () => deleteJson<{ deleted: number }>(tracePath(id)),
    onSuccess: () => {
      client.removeQueries({ queryKey: ['trace-raw', id] })
      return client.invalidateQueries({ queryKey: ['trace', id] })
    },
  })
}

export function useDeleteInvestigation() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => deleteJson<void>(`/api/investigations/${id}`),
    onSuccess: (_, id) => {
      client.removeQueries({ queryKey: ['investigation', String(id)] })
      client.removeQueries({ queryKey: ['dashboard', String(id)] })
      client.removeQueries({ queryKey: ['trace', String(id)] })
      return client.invalidateQueries({ queryKey: ['investigations'] })
    },
  })
}

/** Ask the pipeline to stop the running investigation. The stop is cooperative: the
 * pipeline sees the flag on its next between-docs check and halts the run cleanly,
 * leaving the investigation in PAUSED so Resume continues from where it stopped. */
export function useCancelInvestigation() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => postJson<{ status: string }>(`/api/investigations/${id}/cancel`, {}),
    onSuccess: (_, id) => {
      client.invalidateQueries({ queryKey: ['investigation', String(id)] })
      client.invalidateQueries({ queryKey: ['dashboard', String(id)] })
      client.invalidateQueries({ queryKey: ['live-tree', id] })
      return client.invalidateQueries({ queryKey: ['investigations'] })
    },
  })
}

export const useSources = () => useQuery({ queryKey: ['sources'], queryFn: () => apiFetch<Source[]>('/api/sources') })

/**
 * The two bulk publisher actions.
 *
 * Both change what the confidence numbers mean, so both are a GET that proposes and explains
 * plus a POST that applies. Reading never changes anything; the queries below are safe on every
 * page load. Applying invalidates everything, because rescoring moves every fact on screen.
 */
export const useGradeableSources = () =>
  useQuery({ queryKey: ['sources', 'gradeable'], queryFn: () => apiFetch<GradeableSources>('/api/sources/gradeable') })

export const useDuplicateSources = () =>
  useQuery({ queryKey: ['sources', 'duplicates'], queryFn: () => apiFetch<DuplicateSources>('/api/sources/duplicates') })

export function useRateKnownSources() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: () => postJson<{ graded: number; job: Job }>('/api/sources/rate-known', {}),
    onSuccess: () => void client.invalidateQueries(),
  })
}

export function useMergeDuplicateSources() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (orgKeys: string[] = []) =>
      postJson<{ groups: number; rows_merged: number; documents_moved: number; job: Job }>(
        '/api/sources/merge-duplicates', { org_keys: orgKeys }),
    onSuccess: () => void client.invalidateQueries(),
  })
}

export const useSettings = () => useQuery({ queryKey: ['settings'], queryFn: () => apiFetch<Settings>('/api/settings') })

/** Save the LLM provider settings to argus.toml. The answer has the shape of GET /api/settings. */
export function useSaveLlmSettings() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (body: LlmUpdate) => putJson<Settings>('/api/settings/llm', body),
    onSuccess: (settings) => {
      client.setQueryData(['settings'], settings)
      return client.invalidateQueries({ queryKey: ['settings'] })
    },
  })
}

/** Probe the Ollama server or the claude binary. Nothing is saved. */
export const useTestLlm = () =>
  useMutation({ mutationFn: (body: LlmTestRequest) => postJson<LlmTestResult>('/api/settings/llm/test', body) })

export const useJobs = () =>
  useQuery({
    queryKey: ['jobs'],
    queryFn: () => apiFetch<Job[]>('/api/jobs'),
    refetchInterval: (query) => (query.state.data?.some(isActiveJob) ? 2000 : 10000),
  })

/** Jobs and pipeline events across the whole system. Refreshes every 3 s while any job is queued or running. */
export function useLogs(filter: LogsFilter) {
  const { data: jobs } = useJobs() // the unfiltered list: a running job must keep the log live even when a filter hides it
  const live = jobs?.some(isActiveJob) ?? false
  return useQuery({
    queryKey: ['logs', filter.kind ?? '', filter.state ?? '', filter.since ?? ''],
    queryFn: () => apiFetch<LogsResponse>(`/api/logs${queryString({ kind: filter.kind, state: filter.state, since: filter.since, limit: 200, per_stage_limit: 30 })}`),
    refetchInterval: live ? 3000 : false,
    placeholderData: keepPreviousData,
  })
}

/**
 * A refusal for a missing prerequisite (409 for ATT&CK data, 503 for the Claude Code CLI) means the settings the
 * page checked are out of date: refresh them, so the setup notice and its fix appear instead of a dead-end error.
 */
function refreshSettingsOnRefusal(client: ReturnType<typeof useQueryClient>) {
  return (error: Error) => {
    if (error instanceof ApiError && (error.status === 409 || error.status === 503)) {
      void client.invalidateQueries({ queryKey: ['settings'] })
    }
  }
}

export function useStartJob() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (body: JobRequest) => postJson<Job>('/api/jobs', body),
    onSuccess: () => client.invalidateQueries({ queryKey: ['jobs'] }),
    onError: refreshSettingsOnRefusal(client),
  })
}

export function useUpload() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ files, target }: { files: File[]; target: string }) => {
      const form = new FormData()
      for (const file of files) form.append('files', file)
      if (target.trim()) form.append('target', target.trim())
      return apiFetch<Job>('/api/ingest', { method: 'POST', body: form })
    },
    onSuccess: () => client.invalidateQueries({ queryKey: ['jobs'] }),
    onError: refreshSettingsOnRefusal(client),
  })
}

export function useUpdateSource() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, reliability }: { id: number; reliability: string }) =>
      putJson<SourceUpdate>(`/api/sources/${id}`, { reliability }),
    onSuccess: (saved) => {
      // Show the saved value at once: a refetch can be cut short by the recompute job's own refresh when it ends.
      client.setQueryData<Source[]>(['sources'], (sources) =>
        sources?.map((source) => (source.id === saved.id ? { ...source, reliability: saved.reliability } : source)))
      void client.invalidateQueries() // not awaited: the select stays usable while every page refetches
    },
  })
}

export interface ThreatHistoryInvestigation {
  id: number
  target: string
  state: string
  started_at: string
  finished_at: string | null
}

export interface ThreatHistoryAssessment {
  id: number
  subject_entity_id: string
  object_entity_id: string
  predicate: string
  status: string
  confidence: number
  admiralty: string | null
  first_seen: string | null
  last_seen: string | null
  updated_at: string | null
}

export interface ThreatHistoryAlias {
  alias: string
  origin: string
  investigation_id: number | null
}

export interface ThreatHistory {
  since: string
  investigations: ThreatHistoryInvestigation[]
  new_assessments: ThreatHistoryAssessment[]
  touched_assessments: ThreatHistoryAssessment[]
  new_aliases: ThreatHistoryAlias[]
}

export const useThreatHistory = (id: string | null, since: string | null) =>
  useQuery({
    enabled: !!id,
    queryKey: ['threat-history', id, since],
    queryFn: () => apiFetch<ThreatHistory>(
      `/api/threats/${encodeURIComponent(id!)}/history${queryString({ since: since ?? undefined })}`,
    ),
  })

// -- live pipeline tree (polled while the investigation is still running) ------------------

export type PipelineStageKey = 'collect' | 'triage' | 'analyze' | 'validate'
export type PipelineStageState = 'done' | 'active' | 'queued'
export type PipelineDocState = 'done' | 'running' | 'queued' | 'failed' | 'irrelevant'

export interface PipelineStage {
  key: PipelineStageKey
  state: PipelineStageState
  summary: string
  latest_reason: string | null
}
export interface PipelineDoc {
  document_id: number
  title: string
  url: string | null
  state: PipelineDocState
  facts_count: number
  elapsed_secs: number | null
}
export interface PipelineValidator {
  accepted: number
  rejected: number
  captured_as_sector: number
  swapped: number
  latest_reject: string | null
  latest_capture: string | null
}
export interface PipelineTotals {
  claims: number
  docs_analyzed: number
  docs_remaining: number
}
export interface LivePipelineTree {
  investigation_id: number
  target: string
  state: 'running' | 'paused' | 'finished'
  elapsed_secs: number
  prompt_version: string | null
  stages: PipelineStage[]
  docs: PipelineDoc[]
  validator: PipelineValidator
  totals: PipelineTotals
}

/** Poll every 2s while the pipeline is still running; stop polling once finished.
 * `null` id disables the query (used when the actor has no attached investigation). */
export const useLivePipelineTree = (investigationId: number | null) =>
  useQuery({
    queryKey: ['live-tree', investigationId],
    queryFn: () => apiFetch<LivePipelineTree>(`/api/investigations/${investigationId}/live-tree`),
    enabled: investigationId !== null,
    refetchInterval: (query) => {
      const d = query.state.data as LivePipelineTree | undefined
      return d && d.state === 'finished' ? false : 2000
    },
  })

// -- enrichment -----------------------------------------------------------------------------

export const useEnrichers = () =>
  useQuery({ queryKey: ['enrichers'], queryFn: () => apiFetch<{ enrichers: Enricher[] }>('/api/enrichers') })

export interface ToggleEnricherVars {
  name: string
  enabled: boolean
  /** Optional for key-gated enrichers (VirusTotal). The masked value "••••••••" preserves the stored key. */
  api_key?: string
  env_api_key?: string
}

export function useToggleEnricher() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ name, enabled, api_key, env_api_key }: ToggleEnricherVars) => {
      const body: Record<string, unknown> = { enabled }
      if (api_key !== undefined) body.api_key = api_key
      if (env_api_key !== undefined) body.env_api_key = env_api_key
      return putJson<Enricher>(`/api/enrichers/${encodeURIComponent(name)}`, body)
    },
    onSuccess: () => client.invalidateQueries({ queryKey: ['enrichers'] }),
  })
}

// -- External CTI sources (MISP) --------------------------------------------------------

export const useMispServers = () =>
  useQuery({ queryKey: ['settings', 'misp'], queryFn: () => apiFetch<{ servers: MispServer[] }>('/api/settings/misp') })

export function useSaveMispServers() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (servers: MispServer[]) =>
      putJson<{ servers: MispServer[] }>('/api/settings/misp', { servers }),
    onSuccess: () => client.invalidateQueries({ queryKey: ['settings', 'misp'] }),
  })
}

export const useTestMispServer = () =>
  useMutation({ mutationFn: (server: MispServer) => postJson<SourceTestResult>('/api/settings/misp/test', server) })

// -- External CTI sources (TAXII subscriber) --------------------------------------------

export const useTaxiiServers = () =>
  useQuery({ queryKey: ['settings', 'taxii'], queryFn: () => apiFetch<{ servers: TaxiiServer[] }>('/api/settings/taxii') })

export function useSaveTaxiiServers() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (servers: TaxiiServer[]) =>
      putJson<{ servers: TaxiiServer[] }>('/api/settings/taxii', { servers }),
    onSuccess: () => client.invalidateQueries({ queryKey: ['settings', 'taxii'] }),
  })
}

export const useTestTaxiiServer = () =>
  useMutation({ mutationFn: (server: TaxiiServer) => postJson<SourceTestResult>('/api/settings/taxii/test', server) })

// -- Outbound webhooks ------------------------------------------------------------------

export const useWebhooks = () =>
  useQuery({ queryKey: ['settings', 'webhooks'], queryFn: () => apiFetch<{ webhooks: Webhook[] }>('/api/settings/webhooks') })

export function useSaveWebhooks() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (webhooks: Webhook[]) =>
      putJson<{ webhooks: Webhook[] }>('/api/settings/webhooks', { webhooks }),
    onSuccess: () => client.invalidateQueries({ queryKey: ['settings', 'webhooks'] }),
  })
}

export const useTestWebhook = () =>
  useMutation({ mutationFn: (hook: Webhook) => postJson<SourceTestResult>('/api/settings/webhooks/test', hook) })

export function useInvokeEnricher() {
  return useMutation({
    mutationFn: ({ name, indicator, indicator_type }: { name: string; indicator: string; indicator_type: StixObservableType }) =>
      postJson<EnrichmentResult>(`/api/enrichers/${encodeURIComponent(name)}/invoke`, { indicator, indicator_type }),
  })
}

// -- TLP on publishers ---------------------------------------------------------------------

export function useSetSourceTlp() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, tlp }: { id: number; tlp: Tlp | null }) =>
      putJson<Source>(`/api/sources/${id}/tlp`, { tlp }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['sources'] }),
  })
}

// -- Identity attributes & query ------------------------------------------------------------

export function useSetIdentityAttributes() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, attrs }: { id: string; attrs: IdentityAttributes }) =>
      putJson<{ id: string; attributes: Record<string, string> }>(
        `/api/entities/${encodeURIComponent(id)}/attributes`, attrs,
      ),
    onSuccess: () => void client.invalidateQueries(),
  })
}

export function useQueryTargets(sector: string, country: string) {
  const q = queryString({ sector: sector.trim() || undefined, country: country.trim() || undefined })
  return useQuery({
    queryKey: ['query-targets', sector, country],
    queryFn: () => apiFetch<{
      actors: ActorTargetsRow[]
      matched_identities: number
      matched_by_sectors_attribute?: number
    }>(`/api/query/targets${q}`),
    enabled: Boolean(sector.trim() || country.trim()),
  })
}

// -- STIX import ----------------------------------------------------------------------------

export function useImportStix() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (file: File) => {
      const form = new FormData()
      form.append('bundle', file)
      return apiFetch<StixImportReport>('/api/import/stix', { method: 'POST', body: form })
    },
    onSuccess: () => void client.invalidateQueries(),
  })
}

// -- Entity merge (admin action) ------------------------------------------------------------

export function useMergeEntities() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ source, target }: { source: string; target: string }) =>
      postJson<{ source: string; target: string; recomputed: number }>(
        '/api/entities/merge', { source, target },
      ),
    onSuccess: () => void client.invalidateQueries(),
  })
}

/**
 * The server's clock, ticking locally. Fetches `GET /api/time` once, pins the offset between the
 * server clock and this browser's clock, then advances a Date every second from that offset — so a
 * skewed client clock still shows the right server time. Watcher cron expressions run on the
 * server's UTC clock (`scheduler.py` uses `datetime.now(UTC)`), which is what the header must show.
 */
export function useServerTime(): { now: Date | null; tz: string } {
  const query = useQuery({
    queryKey: ['server-time'],
    queryFn: () => apiFetch<{ now: string; tz: string }>('/api/time'),
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  })
  const [offsetMs, setOffsetMs] = useState<number | null>(null)
  const [now, setNow] = useState<Date | null>(null)

  useEffect(() => {
    if (!query.data) return
    const serverMs = Date.parse(query.data.now)
    if (!Number.isNaN(serverMs)) setOffsetMs(serverMs - Date.now())
  }, [query.data])

  useEffect(() => {
    if (offsetMs === null) return
    const tick = () => setNow(new Date(Date.now() + offsetMs))
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [offsetMs])

  return { now, tz: query.data?.tz ?? 'UTC' }
}
