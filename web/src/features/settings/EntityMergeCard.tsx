import { useState } from 'react'
import { useMergeEntities } from '../../api/hooks'
import { Card } from '../../components/Card'

/** Admin action: fuse two duplicate entities. The classic use is cleaning up a document-origin
 * duplicate that appeared when the Analyst extracted a name before `argus attack update` loaded
 * the MITRE catalog. Danger zone: deletes `source`, moves its claims and aliases into `target`,
 * then recomputes the affected assessments. */
export function EntityMergeCard() {
  const merge = useMergeEntities()
  const [source, setSource] = useState('')
  const [target, setTarget] = useState('')
  const [confirm, setConfirm] = useState(false)
  const [outcome, setOutcome] = useState<string | null>(null)

  const canSubmit = source.trim().length > 0 && target.trim().length > 0 && confirm && !merge.isPending

  return (
    <Card title="Entity merge (admin)">
      <p className="text-xs text-gray-400 mb-3">
        Fuse two entities of the SAME STIX type into one. Classic case: a document-origin
        duplicate of a MITRE Campaign (C0027, …) and the official ATT&CK entity live side by
        side after an `argus attack update`. This operation deletes <em>source</em>, moves its
        claims and aliases into <em>target</em>, and recomputes affected assessments.
      </p>
      <div className="flex flex-col gap-2">
        <label className="text-xs text-gray-400">
          Source (name, alias or entity id — will be deleted):
          <input className="input w-full" value={source} onChange={(e) => setSource(e.target.value)} />
        </label>
        <label className="text-xs text-gray-400">
          Target (name, alias or entity id — survives):
          <input className="input w-full" value={target} onChange={(e) => setTarget(e.target.value)} />
        </label>
        <label className="inline-flex items-center gap-2 text-xs text-yellow-400">
          <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />
          Yes, delete <strong>{source || '<source>'}</strong> and move everything into{' '}
          <strong>{target || '<target>'}</strong>.
        </label>
        <button
          type="button"
          className="btn btn-primary btn-sm w-fit"
          disabled={!canSubmit}
          onClick={() => {
            setOutcome(null)
            merge.mutate({ source: source.trim(), target: target.trim() }, {
              onSuccess: (result) => setOutcome(
                `Merged ${result.source} into ${result.target}. Recomputed ${result.recomputed} assessment(s).`,
              ),
            })
          }}
        >
          {merge.isPending ? 'Merging…' : 'Merge entities'}
        </button>
        {merge.error && <p className="text-sm text-red-400" role="alert">{merge.error.message}</p>}
        {outcome && <p className="text-sm text-emerald-400">{outcome}</p>}
      </div>
    </Card>
  )
}
