import { useEffect, useRef, useState } from 'react'
import { useThreat } from '../../api/hooks'
import type { EntityDetail, Freshness, ScopeParam } from '../../api/types'
import { ApiError } from '../../api/client'
import { Card } from '../../components/Card'
import { EmptyState, ErrorCard, Loading } from '../../components/QueryState'
import { ExternalLink } from '../../components/ExternalLink'
import { CitationsPanel } from '../threats/CitationsPanel'
import { FactsTable, factKey } from '../threats/FactsTable'

/** ATT&CK URLs: sub-techniques live at /techniques/T1566/004/. */
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/

const FRESHNESS_STYLE: Record<Freshness, string> = {
  active: 'bg-emerald-900/40 text-emerald-300',
  dormant: 'bg-amber-900/40 text-amber-300',
  historical: 'bg-gray-700 text-gray-300',
  unknown: 'border border-gray-600 text-gray-400',
}

function FreshnessPill({ value }: { value: Freshness }) {
  return <span className={`px-2 py-0.5 rounded text-xs ${FRESHNESS_STYLE[value]}`}>{value}</span>
}

/** Type-specific facts from `entity.detail`; renders nothing when the entity has none. */
function TypeDetail({ detail }: { detail: EntityDetail | undefined }) {
  if (!detail) return null
  if ('kind' in detail) {
    return (
      <Card title="Indicator">
        <div className="text-sm space-y-1">
          <p>Value: <code className="break-all">{detail.value}</code></p>
          <p>Kind: {detail.kind}</p>
          <p>
            Freshness: <FreshnessPill value={detail.freshness} />{' '}
            {detail.freshness === 'unknown' || !detail.last_seen ? '(no dated citation)' : `(last seen ${detail.last_seen})`}
          </p>
        </div>
      </Card>
    )
  }
  if ('cve_id' in detail) {
    return (
      <Card title="Vulnerability">
        <p className="text-sm">
          CVE: <code>{detail.cve_id}</code>{' '}
          <ExternalLink href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(detail.cve_id)}`}>NVD</ExternalLink>
        </p>
      </Card>
    )
  }
  if (detail.sector_hint) {
    return <Card title="Identity"><p className="text-sm">Sector: {detail.sector_hint}</p></Card>
  }
  return null
}

/** Right-side overlay for one entity. `null` closes it. Everything from the knowledge base is rendered as React text. */
export function EntityDetailPanel({ entityId, onClose, scope }: { entityId: string | null; onClose: () => void; scope?: ScopeParam }) {
  useEffect(() => {
    if (entityId === null) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [entityId, onClose])
  if (entityId === null) return null
  return <PanelBody key={entityId} entityId={entityId} onClose={onClose} scope={scope} />
}

function PanelBody({ entityId, onClose, scope }: { entityId: string; onClose: () => void; scope?: ScopeParam }) {
  const { data, error, isLoading } = useThreat(entityId, scope)
  const [selected, setSelected] = useState<string | null>(null)
  const closeButton = useRef<HTMLButtonElement>(null)
  useEffect(() => closeButton.current?.focus(), [])
  const selectedFact = data?.facts.find((fact) => factKey(fact) === selected) ?? null
  const notFound = error instanceof ApiError && error.status === 404
  const externalId = data?.entity.external_id ?? null
  const techniquePath = externalId && data?.entity.stix_type === 'attack-pattern' && TECHNIQUE.test(externalId)
    ? `techniques/${externalId.replace('.', '/')}/`
    : null

  return (
    <>
      <div data-testid="entity-panel-backdrop" className="fixed inset-0 z-[60] bg-black/40" onClick={onClose} />
      <aside role="dialog" aria-label="Entity details"
        className="fixed inset-y-0 right-0 z-[70] w-[480px] max-w-full overflow-y-auto bg-gray-900 border-l border-gray-700 p-5 space-y-4">
        <div className="flex items-start justify-between gap-4">
          {data ? (
            <div>
              <h2 className="text-xl font-semibold">{data.entity.name}</h2>
              <p className="text-sm text-gray-400">
                {data.entity.stix_type}{externalId ? ` · ${externalId}` : ''}{data.entity.attack ? ' · MITRE ATT&CK' : ''}
              </p>
              {techniquePath && (
                <p className="text-xs mt-1">
                  <ExternalLink href={`https://attack.mitre.org/${techniquePath}`}>attack.mitre.org/{techniquePath}</ExternalLink>
                </p>
              )}
            </div>
          ) : <div />}
          <button ref={closeButton} type="button" className="btn btn-secondary btn-sm" onClick={onClose}>Close</button>
        </div>
        {isLoading ? <Loading /> : notFound ? (
          <Card>
            <EmptyState>This entity was not found in the knowledge base.</EmptyState>
            <div className="text-center"><button type="button" className="btn btn-secondary btn-sm" onClick={onClose}>Close</button></div>
          </Card>
        ) : error || !data ? <ErrorCard error={error} /> : (
          <>
            <TypeDetail detail={data.detail} />
            {data.aliases.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {data.aliases.map((alias) => (
                  <span key={alias.alias} title={`alias origin: ${alias.origin}`}
                    className={`px-2 py-0.5 rounded text-xs ${alias.origin === 'document' ? 'bg-yellow-900/40 text-yellow-300' : 'bg-gray-700 text-gray-300'}`}>
                    {alias.alias}
                  </span>
                ))}
              </div>
            )}
            {data.facts.length === 0 ? (
              <Card><EmptyState>No facts yet for this entity.</EmptyState></Card>
            ) : (
              <>
                <Card title="Facts">
                  <div className="overflow-x-auto">
                    <FactsTable facts={data.facts} entityId={data.entity.id} selected={selected} onSelect={setSelected} />
                  </div>
                </Card>
                <CitationsPanel fact={selectedFact} />
              </>
            )}
          </>
        )}
      </aside>
    </>
  )
}
