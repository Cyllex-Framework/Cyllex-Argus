import {
  useDuplicateSources, useGradeableSources, useMergeDuplicateSources, useRateKnownSources,
} from '../../api/hooks'
import type { DuplicateSourceGroup, SourceProposal } from '../../api/types'
import { Card } from '../../components/Card'
import type { Recompute } from './recompute'

/**
 * The two things an operator can do to this store that change what every confidence number
 * means. Both were CLI-only, which is to say unreachable: this is where the sources are read,
 * so this is where the fix belongs.
 *
 * Each card renders nothing when there is nothing to do. A page that always shows two
 * exhortations trains the eye to skip them.
 */

/** Grade A..F, with the colour the grade deserves. F is a warning, not a neutral. */
const GRADE_TONE: Record<string, string> = {
  A: 'text-emerald-300', B: 'text-emerald-400', C: 'text-sky-300',
  D: 'text-amber-300', E: 'text-amber-400', F: 'text-rose-300',
}

function Grade({ letter }: { letter: string }) {
  return <span className={`font-mono font-semibold ${GRADE_TONE[letter] ?? 'text-gray-300'}`}>{letter}</span>
}

export function GradeKnownSourcesCard({ recompute }: { recompute: Recompute }) {
  const { data } = useGradeableSources()
  const rate = useRateKnownSources()
  const proposals = data?.proposals ?? []

  // Nothing to propose and nothing left unjudged: the axis is in use, so say nothing.
  if (!data || (proposals.length === 0 && data.unjudged === 0)) return null

  if (proposals.length === 0) {
    return (
      <Card title="Source reliability">
        <p className="text-sm text-gray-400">
          {data.unjudged} publisher{data.unjudged === 1 ? '' : 's'} still unjudged, and Argus has no
          basis to grade {data.unjudged === 1 ? 'it' : 'them'}. In the Admiralty system F means
          “reliability cannot be judged”, and it is the <em>floor</em> that confidence is multiplied
          by — so each one suppresses the confidence of everything it reports until you rate it below.
        </p>
      </Card>
    )
  }

  return (
    <Card title="Source reliability">
      <p className="text-sm text-gray-300">
        <strong>{proposals.length} of your {data.publishers} publishers</strong> are sources Argus
        ships a grade for, and {proposals.length === 1 ? 'it is' : 'they are'} still filed as{' '}
        <Grade letter="F" /> — which does not mean “average”. In the Admiralty system F means
        reliability cannot be judged, and it is the <em>floor</em> that every piece of evidence is
        multiplied by. Leaving a national CERT there holds everything it reports at the bottom of
        the confidence scale.
      </p>
      <p className="mt-2 text-xs text-gray-400">
        Expect confidence to go <strong>up</strong>. It was suppressed by the grade, not by the
        evidence. Your own grades always win: this never replaces one you set yourself, and you can
        change any of them in the table below.
        {data.unrecognised > 0 && (
          <> {data.unrecognised} other{data.unrecognised === 1 ? '' : 's'} stay at F — Argus has no
          basis for those, which is what F is for.</>
        )}
      </p>

      <details className="mt-3 group">
        <summary className="cursor-pointer list-none text-xs text-cyan-400 hover:underline underline-offset-2">
          <span className="group-open:hidden">Review the {proposals.length} proposed grades →</span>
          <span className="hidden group-open:inline">Hide the proposals</span>
        </summary>
        <table className="data-table w-full mt-3">
          <thead><tr><th>Publisher</th><th>Now</th><th>Proposed</th><th>Why</th></tr></thead>
          <tbody>
            {proposals.map((proposal: SourceProposal) => (
              <tr key={proposal.id}>
                <td>{proposal.name}<div className="text-[11px] text-gray-500 font-mono">{proposal.organisation}</div></td>
                <td><Grade letter={proposal.current} /></td>
                <td><Grade letter={proposal.proposed} /></td>
                <td className="text-gray-400">{proposal.rationale}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>

      <div className="mt-4">
        <button type="button" className="btn btn-primary btn-sm" disabled={rate.isPending}
          onClick={() => {
            recompute.reset()
            rate.mutate(undefined, {
              onSuccess: (result) => recompute.follow(
                `Graded ${result.graded} publisher${result.graded === 1 ? '' : 's'}`, result.job,
              ),
            })
          }}>
          {rate.isPending ? 'Grading…' : `Grade ${proposals.length} publisher${proposals.length === 1 ? '' : 's'}`}
        </button>
      </div>
      {rate.error && <p className="mt-2 text-sm text-red-400" role="alert">{rate.error.message}</p>}
    </Card>
  )
}

export function DuplicateSourcesCard({ recompute }: { recompute: Recompute }) {
  const { data } = useDuplicateSources()
  const merge = useMergeDuplicateSources()
  const groups = data?.groups ?? []
  if (groups.length === 0) return null

  const apply = (orgKeys: string[], what: string) => {
    recompute.reset()
    merge.mutate(orgKeys, { onSuccess: (result) => recompute.follow(what, result.job) })
  }

  return (
    <Card title="One organisation, several rows">
      <p className="text-sm text-gray-300">
        <strong>{data?.rows} publisher rows are {groups.length} organisation
        {groups.length === 1 ? '' : 's'}.</strong> Corroboration is counted per publisher row, so
        right now a fact reported by one agency under three bylines reads as three independent
        sources agreeing with each other.
      </p>
      <p className="mt-2 text-xs text-gray-400">
        Expect confidence to go <strong>down</strong> on the facts this touches: a merge can only
        remove supporters, and the scores it lowers were overstated. Nothing is lost — every byline
        is kept, so the old name still finds the source and still appears in citations.
      </p>

      <div className="mt-3 space-y-3">
        {groups.map((group: DuplicateSourceGroup) => (
          <div key={group.org_key} className="rounded border border-gray-700 p-3">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <p className="text-sm text-gray-200">
                  {group.keep.name}
                  <span className="text-xs text-gray-500"> · keeps {group.keep.documents} doc
                    {group.keep.documents === 1 ? '' : 's'}</span>
                </p>
                <p className="text-[11px] text-gray-500 font-mono">{group.org_key}</p>
                <ul className="mt-2 space-y-0.5">
                  {group.drop.map((row) => (
                    <li key={row.id} className="text-xs text-amber-300">
                      + {row.name}
                      <span className="text-gray-500"> ({row.documents} doc{row.documents === 1 ? '' : 's'})</span>
                    </li>
                  ))}
                </ul>
              </div>
              <button type="button" className="btn btn-secondary btn-sm shrink-0" disabled={merge.isPending}
                onClick={() => apply([group.org_key], `Merged ${group.drop.length + 1} rows into ${group.keep.name}`)}>
                Merge
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-4">
        {groups.length > 1 && (
          <button type="button" className="btn btn-primary btn-sm" disabled={merge.isPending}
            onClick={() => apply([], `Merged ${data?.rows} rows into ${groups.length} sources`)}>
            {merge.isPending ? 'Merging…' : `Merge all ${groups.length} organisations`}
          </button>
        )}
      </div>
      {merge.error && <p className="mt-2 text-sm text-red-400" role="alert">{merge.error.message}</p>}
    </Card>
  )
}
