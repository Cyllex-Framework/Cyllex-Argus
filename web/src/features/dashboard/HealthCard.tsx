import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '../../api/client'
import { Card } from '../../components/Card'
import { ConfirmDialog } from '../../components/ConfirmDialog'

interface FailedDoc {
  id: number
  title: string
  publisher: string | null
  failure_reason: string | null
}

interface UntaggedIdentity { id: string; name: string }
interface UnratedPublisher { id: number; name: string }
interface StuckInvestigation { id: number; target: string; state: string; started_at: string }
interface MistypedIdentity { id: string; name: string; suggest: 'tool' | 'sector-tag' }
interface NameCollisionMember { id: string; stix_type: string; external_id: string | null }
interface NameCollision { name: string; entities: NameCollisionMember[] }

interface Health {
  totals: {
    failed_documents: number
    untagged_identities: number
    unrated_publishers: number
    stuck_investigations: number
    likely_mistyped_identities: number
    name_collisions: number
    /** Unrated publishers Argus ships a grade for. Optional so fixtures keep compiling. */
    gradeable_publishers?: number
    /** Publisher rows that are the same organisation, so they corroborate each other. */
    duplicate_publisher_rows?: number
  }
  failed_documents: FailedDoc[]
  untagged_identities: UntaggedIdentity[]
  unrated_publishers: UnratedPublisher[]
  stuck_investigations: StuckInvestigation[]
  likely_mistyped_identities: MistypedIdentity[]
  name_collisions: NameCollision[]
}

/** Inline action for a mistyped identity.
 *
 * - `suggest: "tool"`  → PUT /api/entities/{id}/retype {to:"tool"}, preserves UUID + claims.
 * - `suggest: "sector-tag"` → POST /api/entities/{id}/migrate-to-sector-tag, which appends
 *   the identity's name to each targeting actor's `attributes.sectors` list and then
 *   deletes the identity. Uses the default empty actor_ids so the server resolves the
 *   list via actors_targeting_identity — the common case the operator means by "fix this".
 */
function RetypeInlineButton({ identity }: { identity: MistypedIdentity }) {
  const queryClient = useQueryClient()
  const [feedback, setFeedback] = useState<string | null>(null)
  const [confirmMigrate, setConfirmMigrate] = useState(false)

  const retypeToTool = useMutation({
    mutationFn: () => apiFetch(`/api/entities/${encodeURIComponent(identity.id)}/retype`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to: 'tool' }),
    }),
    onSuccess: () => {
      setFeedback('retyped → tool')
      queryClient.invalidateQueries({ queryKey: ['health'] })
      setTimeout(() => setFeedback(null), 3000)
    },
    onError: (e: Error) => { setFeedback(e.message.slice(0, 60)); setTimeout(() => setFeedback(null), 6000) },
  })

  const migrate = useMutation({
    mutationFn: () => apiFetch<{ tagged_actors: unknown[]; removed_claims: number }>(
      `/api/entities/${encodeURIComponent(identity.id)}/migrate-to-sector-tag`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ actor_ids: [], delete: true }),
      },
    ),
    onSuccess: (data) => {
      setFeedback(`tagged ${data.tagged_actors.length} actor(s), ${data.removed_claims} claims removed`)
      queryClient.invalidateQueries({ queryKey: ['health'] })
      setTimeout(() => setFeedback(null), 4000)
    },
    onError: (e: Error) => { setFeedback(e.message.slice(0, 60)); setTimeout(() => setFeedback(null), 6000) },
  })

  if (identity.suggest === 'sector-tag') {
    return (
      <>
        <button className="btn text-xs" onClick={() => setConfirmMigrate(true)} disabled={migrate.isPending}
          title="Append this sector label to each targeting actor's attributes.sectors list, then delete the identity.">
          {migrate.isPending ? 'migrating…' : 'migrate → sectors[]'}
        </button>
        {feedback && <span className="text-xs text-gray-400 ml-2">{feedback}</span>}
        <ConfirmDialog
          open={confirmMigrate}
          title={`Migrate "${identity.name}" to a sector tag?`}
          confirmLabel="Migrate to sectors[]"
          tone="danger"
          busy={migrate.isPending}
          onClose={() => setConfirmMigrate(false)}
          onConfirm={() => { setConfirmMigrate(false); migrate.mutate() }}
        >
          <p>
            Every actor currently targeting this identity will get
            <strong className="text-gray-100"> {identity.name.toLowerCase()}</strong> appended to its
            <code className="mono"> attributes.sectors</code> list.
          </p>
          <p>The identity entity, its claims and its assessments will then be deleted.</p>
        </ConfirmDialog>
      </>
    )
  }

  return (
    <>
      <button className="btn text-xs" onClick={() => retypeToTool.mutate()} disabled={retypeToTool.isPending}
        title="Change this entity's STIX type from identity to tool, preserving its UUID and every claim/alias pointing at it.">
        {retypeToTool.isPending ? 'retyping…' : 'retype → tool'}
      </button>
      {feedback && <span className="text-xs text-gray-400 ml-2">{feedback}</span>}
    </>
  )
}

/**
 * At-a-glance checklist of repair-worthy state. Four cells, one per category; each shows a
 * count and the first few entries with a direct link to where the operator fixes them.
 * Keeps the dashboard focused on "what should I do next?" without the user having to open
 * three tabs to notice there's something to do at all.
 */
export function HealthCard() {
  const { data, isPending } = useQuery({
    queryKey: ['health'],
    queryFn: () => apiFetch<Health>('/api/health'),
    refetchInterval: 30_000,
  })

  if (isPending || !data) {
    return (
      <Card title="Data health">
        <p className="text-sm text-gray-500">Loading…</p>
      </Card>
    )
  }

  const clean =
    data.totals.failed_documents === 0 &&
    data.totals.untagged_identities === 0 &&
    data.totals.unrated_publishers === 0 &&
    data.totals.stuck_investigations === 0 &&
    data.totals.likely_mistyped_identities === 0 &&
    data.totals.name_collisions === 0

  // Both word forms are spelled out: "identity" + "s" would read "untagged identitys".
  const chips: { one: string; many: string; count: number; tone: string }[] = [
    { one: 'failed document', many: 'failed documents', count: data.totals.failed_documents, tone: 'text-rose-300' },
    { one: 'untagged identity', many: 'untagged identities', count: data.totals.untagged_identities, tone: 'text-amber-300' },
    { one: 'unrated publisher', many: 'unrated publishers', count: data.totals.unrated_publishers, tone: 'text-sky-300' },
    { one: 'stuck run', many: 'stuck runs', count: data.totals.stuck_investigations, tone: 'text-violet-300' },
    { one: 'likely mistyped identity', many: 'likely mistyped identities', count: data.totals.likely_mistyped_identities, tone: 'text-amber-300' },
    { one: 'name collision', many: 'name collisions', count: data.totals.name_collisions, tone: 'text-gray-300' },
    // The two actionable publisher counts. They sit after the plain "unrated publishers" count
    // because they are what to DO about it: one click each, on the Sources page.
    { one: 'publisher Argus can grade', many: 'publishers Argus can grade',
      count: data.totals.gradeable_publishers ?? 0, tone: 'text-emerald-300' },
    { one: 'duplicate publisher row', many: 'duplicate publisher rows',
      count: data.totals.duplicate_publisher_rows ?? 0, tone: 'text-orange-300' },
  ].filter((chip) => chip.count > 0)

  return (
    <Card title="Data health">
      {clean ? (
        <p className="text-sm text-emerald-400">Nothing to clean up — all documents validated, every identity tagged, every publisher rated.</p>
      ) : (
        // Collapsed by default. Expanded, this is four columns of lists plus a collisions table:
        // useful when the operator comes to clean up, overwhelming when they came to read
        // intelligence. The counts alone answer "is there anything to do?" in one line.
        <details className="group">
          <summary className="flex flex-wrap items-baseline gap-x-4 gap-y-1 cursor-pointer list-none">
            {chips.map((chip, index) => (
              <span key={chip.many} className="text-sm text-gray-400">
                {index > 0 && <span className="mr-4 text-gray-700" aria-hidden="true">·</span>}
                <span className={`font-mono font-semibold tabular-nums ${chip.tone}`}>{chip.count}</span>
                {' '}{chip.count === 1 ? chip.one : chip.many}
              </span>
            ))}
            <span className="ml-auto text-xs font-medium text-purple-400 group-hover:underline underline-offset-2 shrink-0">
              <span className="group-open:hidden">Show details →</span>
              <span className="hidden group-open:inline">Hide details</span>
            </span>
          </summary>
          <div className="mt-5 space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
              <Section
                label="Failed documents"
                count={data.totals.failed_documents}
                tone="rose"
                help="Re-run with the Retry button on the Documents page"
                fixTo="/documents?stage=failed"
              >
                {data.failed_documents.slice(0, 5).map((d) => (
                  <li key={d.id} className="text-sm">
                    <Link to={`/documents/${d.id}`} className="text-purple-400 hover:underline">{d.title}</Link>
                    {d.failure_reason && <div className="text-xs text-rose-300/80">{d.failure_reason}</div>}
                  </li>
                ))}
              </Section>

              <Section
                label="Untagged identities"
                count={data.totals.untagged_identities}
                tone="amber"
                help="Tag with sector + country to populate Query targets"
              >
                {data.untagged_identities.slice(0, 5).map((e) => (
                  <li key={e.id} className="text-sm">
                    <Link to={`/threats/${encodeURIComponent(e.id)}`} className="text-purple-400 hover:underline">{e.name}</Link>
                  </li>
                ))}
              </Section>

              <Section
                label="Unrated publishers"
                count={data.totals.unrated_publishers}
                tone="sky"
                help="Rate A–F to unlock confidence scoring"
                fixTo="/sources"
              >
                {data.unrated_publishers.slice(0, 5).map((p) => (
                  <li key={p.id} className="text-sm">
                    <Link to="/sources" className="text-purple-400 hover:underline">{p.name}</Link>
                  </li>
                ))}
              </Section>

              <Section
                label="Stuck investigations"
                count={data.totals.stuck_investigations}
                tone="violet"
                help="Running or paused — Resume to continue"
              >
                {data.stuck_investigations.slice(0, 5).map((inv) => (
                  <li key={inv.id} className="text-sm">
                    <Link to={`/investigations/${inv.id}/dashboard`} className="text-purple-400 hover:underline">
                      {inv.target}
                    </Link>
                    <span className="text-xs text-gray-500"> · {inv.state}</span>
                  </li>
                ))}
              </Section>
            </div>
            <PublisherHousekeeping totals={data.totals} />
            {data.likely_mistyped_identities.length > 0 && (
              <MistypedIdentitiesSection identities={data.likely_mistyped_identities} />
            )}
            {data.name_collisions.length > 0 && (
              <NameCollisionsSection collisions={data.name_collisions} />
            )}
          </div>
        </details>
      )}
    </Card>
  )
}

interface BatchResult { ok: unknown[]; failed: unknown[]; total: number }

/** Mistyped-identities section with per-row buttons AND two bulk actions:
 *  "Retype all N tools" and "Migrate all N sectors". The bulk buttons call the
 *  batch endpoints (hard cap: 100 for retype, 50 for sectors) and show the
 *  per-category count so the operator knows what the single click will do.
 */
function MistypedIdentitiesSection({ identities }: { identities: MistypedIdentity[] }) {
  const queryClient = useQueryClient()
  const [feedback, setFeedback] = useState<string | null>(null)
  const [confirmBulk, setConfirmBulk] = useState<'retype' | 'migrate' | null>(null)
  const tools = identities.filter((i) => i.suggest === 'tool')
  const sectors = identities.filter((i) => i.suggest === 'sector-tag')

  const retypeAll = useMutation({
    mutationFn: () => apiFetch<BatchResult>('/api/entities/retype-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        items: tools.slice(0, 100).map((t) => ({ entity_id: t.id, to: 'tool' })),
      }),
    }),
    onSuccess: (data) => {
      setFeedback(`retyped ${data.ok.length}/${data.total}${data.failed.length ? `, ${data.failed.length} failed` : ''}`)
      queryClient.invalidateQueries({ queryKey: ['health'] })
      setTimeout(() => setFeedback(null), 5000)
    },
    onError: (e: Error) => { setFeedback(e.message.slice(0, 80)); setTimeout(() => setFeedback(null), 6000) },
  })

  const migrateAll = useMutation({
    mutationFn: () => apiFetch<BatchResult>('/api/entities/migrate-sectors-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identity_ids: sectors.slice(0, 50).map((s) => s.id) }),
    }),
    onSuccess: (data) => {
      setFeedback(`migrated ${data.ok.length}/${data.total}${data.failed.length ? `, ${data.failed.length} failed` : ''}`)
      queryClient.invalidateQueries({ queryKey: ['health'] })
      setTimeout(() => setFeedback(null), 5000)
    },
    onError: (e: Error) => { setFeedback(e.message.slice(0, 80)); setTimeout(() => setFeedback(null), 6000) },
  })

  const confirmBulkRetype = () => setConfirmBulk('retype')
  const confirmBulkMigrate = () => setConfirmBulk('migrate')

  return (
    <div className="mt-6 pt-4 border-t border-gray-800">
      <div className="flex items-baseline justify-between mb-2 gap-4 flex-wrap">
        <div className="text-sm font-semibold text-orange-300">
          Likely mistyped identities <span className="text-xs text-gray-500">· {identities.length}</span>
        </div>
        <div className="flex gap-2 items-center">
          {tools.length > 0 && (
            <button className="btn text-xs" onClick={confirmBulkRetype} disabled={retypeAll.isPending}>
              {retypeAll.isPending ? 'retyping…' : `Retype all ${Math.min(tools.length, 100)} tools`}
            </button>
          )}
          {sectors.length > 0 && (
            <button className="btn text-xs" onClick={confirmBulkMigrate} disabled={migrateAll.isPending}>
              {migrateAll.isPending ? 'migrating…' : `Migrate all ${Math.min(sectors.length, 50)} sectors`}
            </button>
          )}
          {feedback && <span className="text-xs text-gray-400">{feedback}</span>}
        </div>
      </div>
      <p className="text-xs text-gray-500 mb-3 italic">
        The Analyst extracted these as `identity` SDOs but their names look like tools
        (AWS, Cloudflare, …) or sector labels. Retype the tools in place; sector labels get
        migrated to the targeting actor&apos;s <code className="mono">attributes.sectors[]</code>.
      </p>
      <table className="data-table w-full">
        <thead><tr><th>Name</th><th>Current</th><th>Suggested</th><th></th></tr></thead>
        <tbody>
          {identities.slice(0, 10).map((e) => (
            <tr key={e.id}>
              <td>
                <Link to={`/threats/${encodeURIComponent(e.id)}`} className="text-purple-400 hover:underline">{e.name}</Link>
              </td>
              <td className="text-xs text-gray-400">identity</td>
              <td className="text-xs text-emerald-400">{e.suggest}</td>
              <td><RetypeInlineButton identity={e} /></td>
            </tr>
          ))}
        </tbody>
      </table>
      {identities.length > 10 && (
        <p className="text-xs text-gray-500 mt-2">… and {identities.length - 10} more. The bulk buttons above cover up to the per-batch cap.</p>
      )}
      <ConfirmDialog
        open={confirmBulk === 'retype'}
        title={`Retype ${tools.length} identities to tool?`}
        confirmLabel="Retype all"
        tone="danger"
        busy={retypeAll.isPending}
        onClose={() => setConfirmBulk(null)}
        onConfirm={() => { setConfirmBulk(null); retypeAll.mutate() }}
      >
        <p>Retype {tools.length} identity entities to <strong className="text-gray-100">tool</strong> in one batch.</p>
        <p>
          Each entity's UUID is preserved; every claim/alias pointing at it is rewritten in the same
          transaction. ATT&amp;CK-origin entities are rejected individually.
        </p>
      </ConfirmDialog>
      <ConfirmDialog
        open={confirmBulk === 'migrate'}
        title={`Migrate ${sectors.length} sector identities?`}
        confirmLabel="Migrate all"
        tone="danger"
        busy={migrateAll.isPending}
        onClose={() => setConfirmBulk(null)}
        onConfirm={() => { setConfirmBulk(null); migrateAll.mutate() }}
      >
        <p>Migrate {sectors.length} sector-identity entities to <code className="mono">actor.sectors[]</code> in one batch.</p>
        <p>
          For each identity: every actor currently targeting it gets the sector label appended, then the
          identity + its claims + assessments are deleted.
        </p>
      </ConfirmDialog>
    </div>
  )
}

/** Shows the actor+malware (and other cross-type) name collisions. Each row lists both
 * entities so the operator can see which one is at risk of mis-attribution — then click
 * through to the one they actually opened to confirm the facts went to the right place. */
function NameCollisionsSection({ collisions }: { collisions: NameCollision[] }) {
  return (
    <div className="mt-6 pt-4 border-t border-gray-800">
      <div className="text-sm font-semibold text-indigo-300 mb-2">
        Name collisions <span className="text-xs text-gray-500">· {collisions.length}</span>
      </div>
      <p className="text-xs text-gray-500 mb-3 italic">
        These entities share a canonical name across STIX types (actor + malware is the
        common case in ATT&CK: Machete, Carbanak, Akira, …). An investigation that
        targeted one may have attributed facts to the other if the pipeline ran before
        analyst-v3. Open each to verify.
      </p>
      <table className="data-table w-full">
        <thead><tr><th>Name</th><th>Entities</th></tr></thead>
        <tbody>
          {collisions.slice(0, 10).map((c) => (
            <tr key={c.name}>
              <td className="font-semibold">{c.name}</td>
              <td>
                <div className="flex flex-wrap gap-2">
                  {c.entities.map((e) => (
                    <Link key={e.id} to={`/threats/${encodeURIComponent(e.id)}`}
                      className="text-xs px-1.5 py-0.5 rounded bg-gray-800 border border-gray-700 hover:bg-gray-700">
                      {e.stix_type}{e.external_id ? ` · ${e.external_id}` : ''}
                    </Link>
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {collisions.length > 10 && (
        <p className="text-xs text-gray-500 mt-2">… and {collisions.length - 10} more.</p>
      )}
    </div>
  )
}

const TONES: Record<string, string> = {
  rose: 'text-rose-300',
  amber: 'text-amber-300',
  sky: 'text-sky-300',
  violet: 'text-violet-300',
}

function Section({
  label, count, tone, help, fixTo, children,
}: {
  label: string
  count: number
  tone: 'rose' | 'amber' | 'sky' | 'violet'
  help: string
  fixTo?: string
  children: React.ReactNode
}) {
  if (count === 0) {
    return (
      <div className="opacity-50">
        <div className={`text-sm font-semibold ${TONES[tone]}`}>{label} <span className="text-xs text-gray-500">· all clean</span></div>
      </div>
    )
  }
  return (
    <div>
      <div className="flex items-baseline justify-between mb-2">
        <div className={`text-sm font-semibold ${TONES[tone]}`}>
          {label} <span className="text-xs text-gray-500">· {count}</span>
        </div>
        {fixTo && <Link to={fixTo} className="text-xs text-purple-400 hover:underline">fix</Link>}
      </div>
      <ul className="space-y-1">{children}</ul>
      <div className="text-xs text-gray-500 mt-2 italic">{help}</div>
    </div>
  )
}


/**
 * What to do about the publisher counts, with the reason, and a link to where it is done.
 *
 * The house rule: a screen that shows a problem leads to its solution. "38 unrated publishers"
 * states a problem and offers nothing — and in the Admiralty system F is not a neutral middle,
 * it is the floor every piece of evidence is multiplied by, so those 38 are actively holding
 * their own reporting down.
 */
function PublisherHousekeeping({ totals }: { totals: Health['totals'] }) {
  const gradeable = totals.gradeable_publishers ?? 0
  const duplicates = totals.duplicate_publisher_rows ?? 0
  if (gradeable === 0 && duplicates === 0) return null
  return (
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400 mb-2">Publishers</h3>
      <ul className="space-y-2 text-sm text-gray-400">
        {gradeable > 0 && (
          <li>
            <strong className="text-gray-200">{gradeable}</strong> of your unrated publishers are
            sources Argus ships a grade for. F means “reliability cannot be judged” and it is the
            floor confidence is multiplied by, so each one is suppressing everything it reports.{' '}
            <Link to="/sources" className="text-cyan-400 hover:underline underline-offset-2">
              Review the proposed grades →
            </Link>
          </li>
        )}
        {duplicates > 0 && (
          <li>
            <strong className="text-gray-200">{duplicates}</strong> publisher row
            {duplicates === 1 ? '' : 's'} duplicate an organisation this store already has.
            Corroboration is counted per row, so one agency currently reads as several sources
            agreeing.{' '}
            <Link to="/sources" className="text-cyan-400 hover:underline underline-offset-2">
              Review the duplicates →
            </Link>
          </li>
        )}
      </ul>
    </section>
  )
}
