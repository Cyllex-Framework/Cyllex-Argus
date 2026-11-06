/**
 * Quick actions + paused banner for an investigation dashboard. Lives above the Investigation
 * pipeline card so the operator sees Resume / Delete / View threat profile before the long pipeline
 * timeline — the previous layout buried the actions inside the Overview section below the
 * pipeline, which hid the Resume button a user with a recovery-paused run needed to see first.
 */

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useIsReader, useStartJob } from '../../api/hooks'
import type { DashboardEntity, DashboardInvestigation } from '../../api/types'
import { Card } from '../../components/Card'
import { useRemoveInvestigation } from './InvestigationHeader'

export function InvestigationQuickActions({ investigation, entity }: {
  investigation: DashboardInvestigation
  entity: DashboardEntity | null
}) {
  const navigate = useNavigate()
  const { remove, pending, dialog: deleteDialog } = useRemoveInvestigation(investigation)
  const start = useStartJob()
  const isReader = useIsReader()
  const [resumeError, setResumeError] = useState<string | null>(null)
  const running = investigation.state === 'running'
  const paused = investigation.state === 'paused'
  const resume = () => {
    setResumeError(null)
    start.mutate({ kind: 'resume', investigation_id: investigation.id }, {
      onError: (exc) => setResumeError(exc instanceof Error ? exc.message : String(exc)),
    })
  }
  // Readers get no run controls (resume / delete / generate); the server enforces this too.
  if (isReader) return null
  return (
    <div className="space-y-4">
      {deleteDialog}
      {paused && investigation.paused_reason && (
        <div role="status" className="rounded border border-amber-700/40 bg-amber-900/20 p-3 text-sm text-amber-200">
          <div className="font-semibold mb-1">Investigation paused</div>
          <p className="text-amber-300/90">{investigation.paused_reason}</p>
          <p className="mt-2 text-amber-300/60 text-xs">
            Click <strong>Resume</strong> below to continue from where the pipeline stopped —
            documents that already have claims are skipped automatically.
          </p>
        </div>
      )}
      <Card title="Quick actions">
        <div className="flex flex-wrap gap-2">
          {paused && (
            <button type="button" className="btn btn-primary btn-sm" onClick={resume} disabled={start.isPending}>
              {start.isPending ? 'Resuming…' : 'Resume investigation'}
            </button>
          )}
          {entity && (
            <button type="button" className="btn btn-secondary btn-sm"
              onClick={() => navigate(`/threats/${encodeURIComponent(entity.id)}`)}>
              View threat profile
            </button>
          )}
          <button type="button" className="btn btn-secondary btn-sm"
            onClick={() => navigate(`/investigations/${investigation.id}`)}>
            View documents &amp; timeline
          </button>
          <button type="button" className="btn btn-secondary btn-sm text-red-400"
            disabled={pending || running} onClick={remove}
            title={running ? 'Wait until the investigation finishes' : 'Delete this investigation'}>
            Delete investigation
          </button>
        </div>
        {resumeError && <p role="alert" className="mt-2 text-sm text-red-400">{resumeError}</p>}
      </Card>
    </div>
  )
}
