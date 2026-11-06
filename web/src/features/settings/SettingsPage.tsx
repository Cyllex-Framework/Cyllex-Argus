import { useState } from 'react'
import { useActiveJob, useSettings, useStartJob } from '../../api/hooks'
import { Card } from '../../components/Card'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { ErrorCard, Loading } from '../../components/QueryState'
import { DatabaseCard } from './DatabaseCard'
import { EnrichersCard } from './EnrichersCard'
import { EntityMergeCard } from './EntityMergeCard'
import { LlmSettingsCard } from './LlmSettingsCard'
import { LoggingCard } from './LoggingCard'
import { MispServersCard } from './MispServersCard'
import { StixImportCard } from './StixImportCard'
import { TaxiiServersCard } from './TaxiiServersCard'
import { WebhooksCard } from './WebhooksCard'
import { JobPanel } from '../investigations/JobPanel'

const ATTACK_UPDATE = ['attack_update'] as const

type RetainMode = 'off' | 'errors' | 'full'

/** Pull the retention mode out of the opaque config blob the settings endpoint returns. */
function extractRetainMode(config: unknown): RetainMode {
  const logging = (config as { logging?: { retain_raw_llm?: unknown } })?.logging
  const value = logging?.retain_raw_llm
  if (value === 'errors' || value === 'full') return value
  return 'off'  // includes the legacy bool 'false' and any unknown string
}

export function SettingsPage() {
  const { data, error, isLoading } = useSettings()
  const start = useStartJob()
  const [started, setStarted] = useState<string | null>(null)
  const [confirmUpdate, setConfirmUpdate] = useState(false)
  const jobId = useActiveJob(ATTACK_UPDATE, { started })
  if (isLoading) return <Loading />
  if (error || !data) return <ErrorCard error={error} />
  return (
    <div className="grid grid-cols-2 gap-6">
      <div className="space-y-6">
        <Card title="MITRE ATT&CK" actions={
          <button type="button" className="btn btn-primary btn-sm" disabled={start.isPending}
            onClick={() => setConfirmUpdate(true)}>
            Update ATT&CK
          </button>
        }>
          {data.attack.present ? (
            <p className="text-sm text-gray-300">
              {data.attack.techniques} techniques, {data.attack.groups} groups, {data.attack.software} software loaded.
            </p>
          ) : (
            <p className="text-sm text-yellow-400">
              ATT&CK data is missing. Argus maps techniques to MITRE ATT&CK, so update it before investigating or
              ingesting documents.
            </p>
          )}
          {start.error && <p className="text-sm text-red-400 mt-2" role="alert">{start.error.message}</p>}
        </Card>
        <ConfirmDialog
          open={confirmUpdate}
          title="Update MITRE ATT&CK data?"
          confirmLabel="Download & update"
          busy={start.isPending}
          onClose={() => setConfirmUpdate(false)}
          onConfirm={() => start.mutate({ kind: 'attack_update' }, {
            onSuccess: (job) => { setStarted(job.id); setConfirmUpdate(false) },
            onError: () => setConfirmUpdate(false),
          })}
        >
          <p>
            Argus will download the MITRE ATT&CK Enterprise catalogue (~50&nbsp;MB) from MITRE's
            public repository on GitHub and load it into your local store. This is an outbound
            network request — the one reference-data fetch Argus makes; no indicators of yours
            leave the machine.
          </p>
          <p>
            It runs as a background job, so you can keep working; progress appears below. The
            existing catalogue keeps serving until the new one is loaded, and your investigations
            and facts are untouched.
          </p>
        </ConfirmDialog>
        <JobPanel key={jobId ?? 'none'} jobId={jobId} title="ATT&CK update" />
        <LlmSettingsCard llm={data.llm} knownModels={data.known_models ?? {}} />
        <LoggingCard current={extractRetainMode(data.config)} />
        <Card title="Claude Code">
          {data.claude.found ? (
            <p className="text-sm text-gray-300">Claude Code CLI found. Investigations use your Claude subscription.</p>
          ) : (
            <p className="text-sm text-yellow-400">
              Claude Code CLI not found. Install Claude Code, run <code className="mono">claude</code> once to log in,
              then restart <code className="mono">argus serve</code>.
            </p>
          )}
        </Card>
        <Card title="Data directory">
          <p className="mono text-sm text-gray-300 break-all">{data.home}</p>
        </Card>
        <DatabaseCard />
      </div>
      <div className="space-y-6">
        <EnrichersCard />
        <TaxiiServersCard />
        <MispServersCard />
        <WebhooksCard />
        <StixImportCard />
        <EntityMergeCard />
        <Card title="Configuration (argus.toml)">
          <pre className="mono text-xs text-gray-300 whitespace-pre-wrap break-words">{JSON.stringify(data.config, null, 2)}</pre>
        </Card>
      </div>
    </div>
  )
}
