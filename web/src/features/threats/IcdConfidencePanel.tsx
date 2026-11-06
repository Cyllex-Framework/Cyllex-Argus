import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '../../api/client'
import { Card } from '../../components/Card'
import { AnalyticConfidenceBadge } from '../../components/badges'
import type { AnalyticConfidenceLevel, Fact } from '../../api/types'

type FormState = { level: '' | AnalyticConfidenceLevel; rationale: string }

async function putAnalyticConfidence(
  assessmentId: number,
  level: AnalyticConfidenceLevel | null,
  rationale: string | null,
) {
  return apiFetch<{ id: number; analytic_confidence: string | null; confidence_rationale: string | null }>(
    `/api/assessments/${assessmentId}/analytic-confidence`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Argus-CSRF': '1' },
      body: JSON.stringify({ level, rationale }),
    },
  )
}

/**
 * ICD 203 override panel for the currently selected fact.
 *
 * ICD 203 is a judgement about analytic soundness (alternative hypotheses, logic quality,
 * evidence volume), not something a formula can decide. Argus derives a default level from
 * (confidence, status), but the analyst gets the final word via this panel.
 *
 * Clearing (level = "" / "derived") removes the override so the next recompute picks the
 * derived value back up; the backend stores it as NULL + null rationale.
 */
export function IcdConfidencePanel({ fact, threatId }: { fact: Fact | null; threatId: string }) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState<FormState>({ level: '', rationale: '' })
  const [savedAt, setSavedAt] = useState<number | null>(null)

  useEffect(() => {
    setForm({
      level: (fact?.analytic_confidence as AnalyticConfidenceLevel | undefined) ?? '',
      rationale: fact?.confidence_rationale ?? '',
    })
    setSavedAt(null)
  }, [fact?.assessment_id])

  const mutation = useMutation({
    mutationFn: async () => {
      if (!fact?.assessment_id) throw new Error('no assessment id')
      return putAnalyticConfidence(
        fact.assessment_id,
        form.level === '' ? null : form.level,
        form.rationale.trim() === '' ? null : form.rationale.trim(),
      )
    },
    onSuccess: () => {
      setSavedAt(Date.now())
      queryClient.invalidateQueries({ queryKey: ['threat', threatId] })
    },
  })

  if (!fact) {
    return (
      <Card title="ICD 203 confidence">
        <p className="text-xs text-gray-500">Pick a fact to override its analytic confidence.</p>
      </Card>
    )
  }

  if (!fact.assessment_id) {
    return (
      <Card title="ICD 203 confidence">
        <p className="text-xs text-gray-500">This fact has no assessment id yet — ingest more evidence first.</p>
      </Card>
    )
  }

  return (
    <Card title="ICD 203 confidence">
      <div className="space-y-3 text-sm">
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-400">Current:</span>
          <AnalyticConfidenceBadge level={fact.analytic_confidence} rationale={fact.confidence_rationale} />
          <span className="text-xs text-gray-500">
            (derived from confidence {fact.confidence}, status {fact.status})
          </span>
        </div>

        <label className="block">
          <span className="text-xs text-gray-400">Override level</span>
          <select
            className="select w-full mt-1"
            value={form.level}
            onChange={(e) => setForm({ ...form, level: e.target.value as FormState['level'] })}
          >
            <option value="">Derived (clear override)</option>
            <option value="high">HIGH</option>
            <option value="moderate">MODERATE</option>
            <option value="low">LOW</option>
          </select>
        </label>

        <label className="block">
          <span className="text-xs text-gray-400">
            Rationale <span className="text-gray-500">(why the derived value is wrong)</span>
          </span>
          <textarea
            className="input w-full mt-1 min-h-20"
            placeholder="e.g. source predates the 2015 vendor rebrand — attribution no longer applies"
            value={form.rationale}
            maxLength={2000}
            onChange={(e) => setForm({ ...form, rationale: e.target.value })}
          />
          <span className="text-xs text-gray-500">{form.rationale.length}/2000</span>
        </label>

        <div className="flex items-center gap-3">
          <button
            className="btn"
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
          >
            {mutation.isPending ? 'Saving...' : form.level === '' ? 'Clear override' : 'Save override'}
          </button>
          {savedAt && !mutation.isPending && (
            <span className="text-xs text-emerald-400">Saved · panel refreshed</span>
          )}
          {mutation.isError && <span className="text-xs text-rose-400">Failed to save</span>}
        </div>
      </div>
    </Card>
  )
}
