import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useDeleteInvestigation, useInvestigations } from '../../api/hooks'
import { Card } from '../../components/Card'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { JobStatePill } from '../../components/badges'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'
import { TokenUsageBadge } from '../../components/TokenUsageBadge'
import { formatDateTime } from '../../lib/format'
import { NewInvestigationCard, stageSummary } from './NewInvestigationCard'

export function InvestigationsPage() {
  const { data, error, isLoading } = useInvestigations()
  const del = useDeleteInvestigation()
  const [pendingDelete, setPendingDelete] = useState<{ id: number; target: string } | null>(null)
  const remove = (id: number, target: string) => setPendingDelete({ id, target })
  return (
    <div className="space-y-6">
      <NewInvestigationCard />
      <Card title="Investigations">
        {isLoading ? <Loading /> : error || !data ? <ErrorCard error={error} /> : data.length === 0 ? (
          <EmptyState>No investigations yet. Start one above.</EmptyState>
        ) : (
          <table className="data-table w-full">
            <thead><tr><th>#</th><th>Target</th><th>By</th><th>State</th><th>Documents</th><th>LLM usage</th><th>Started</th><th>Finished</th><th aria-label="Actions" /></tr></thead>
            <tbody>
              {data.map((inv) => (
                <tr key={inv.id}>
                  <td className="text-gray-400">{inv.id}</td>
                  <td><Link to={`/investigations/${inv.id}/dashboard`} className="text-purple-400 hover:underline">{inv.target}</Link></td>
                  <td className="text-xs text-gray-400">{inv.started_by}</td>
                  <td><JobStatePill state={inv.state} /></td>
                  <td className="text-xs text-gray-400">{stageSummary(inv.stage_counts)}</td>
                  <td className="text-xs text-gray-400">
                    <TokenUsageBadge usage={inv.token_usage} />
                  </td>
                  <td className="text-xs text-gray-400">{formatDateTime(inv.started_at)}</td>
                  <td className="text-xs text-gray-400">{formatDateTime(inv.finished_at)}</td>
                  <td className="text-right">
                    <button type="button" className="btn btn-secondary btn-sm text-red-400" aria-label={`Delete investigation ${inv.id}`}
                      disabled={del.isPending && del.variables === inv.id} onClick={() => remove(inv.id, inv.target)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <ConfirmDialog
        open={pendingDelete !== null}
        title={`Delete investigation #${pendingDelete?.id}?`}
        confirmLabel="Delete investigation"
        tone="danger"
        busy={del.isPending}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => { if (pendingDelete) del.mutate(pendingDelete.id, { onSuccess: () => setPendingDelete(null) }) }}
      >
        <p>Delete investigation #{pendingDelete?.id} (<strong className="text-gray-100">{pendingDelete?.target}</strong>)?</p>
        <p>Its exclusive documents are removed too; other investigations' data stays.</p>
      </ConfirmDialog>
    </div>
  )
}
