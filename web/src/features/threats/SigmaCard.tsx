import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiRequest } from '../../api/client'
import { Card } from '../../components/Card'

interface SigmaRule {
  id: string
  title: string
  level: string
  tags: string[]
  logsource: { category: string; product: string }
  yaml: string
}

interface SigmaHqRule {
  title: string
  url: string
}

interface SigmaHqReference {
  technique_id: string
  technique_name: string
  count: number
  rules: SigmaHqRule[]
  browse_url: string
}

interface SigmaResponse {
  entity: string
  count: number
  rules: SigmaRule[]
  references: SigmaHqReference[]
}

const LEVEL_TONE: Record<string, string> = {
  critical: 'bg-rose-900/60 text-rose-200',
  high: 'bg-amber-900/60 text-amber-200',
  medium: 'bg-sky-900/60 text-sky-200',
  low: 'bg-gray-700 text-gray-200',
  informational: 'bg-gray-700 text-gray-200',
}

/** Argus -> Sigma: IOC rules Argus owns, plus SigmaHQ references for each observed technique. */
export function SigmaCard({ entityId }: { entityId: string }) {
  const [open, setOpen] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const [downloading, setDownloading] = useState(false)

  const { data, isPending, isError, refetch } = useQuery({
    queryKey: ['sigma', entityId],
    queryFn: () => apiFetch<SigmaResponse>(`/api/threats/${entityId}/detections/sigma`),
    enabled: open,
  })

  if (!open) {
    return (
      <Card title="Sigma detections">
        <p className="text-sm text-gray-400 mb-2">
          One Sigma rule per indicator (IP / domain / URL / hash) with the right log source, plus a
          link to the existing SigmaHQ rules for each observed MITRE technique. Argus does not invent
          a detection per technique; it points you at the community&apos;s vetted ones.
        </p>
        <button className="btn btn-primary btn-sm" onClick={() => setOpen(true)}>Generate Sigma detections</button>
      </Card>
    )
  }

  const downloadAll = async () => {
    setDownloading(true)
    try {
      const res = await apiRequest(`/api/threats/${entityId}/detections/sigma.zip`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const slug = (data?.entity ?? 'threat').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
      const a = document.createElement('a')
      a.href = url
      a.download = `${slug || 'threat'}-sigma.zip`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch {
      // 401 is handled globally by apiRequest; other failures fall through silently
    } finally {
      setDownloading(false)
    }
  }

  const hasRules = !!data && data.count > 0
  const hasRefs = !!data && data.references.length > 0

  return (
    <Card title={`Sigma detections${data ? ` (${data.count})` : ''}`}>
      {isPending && <p className="text-sm text-gray-400">Generating...</p>}
      {isError && (
        <div className="text-sm text-rose-300">
          Failed to generate. <button className="underline" onClick={() => refetch()}>Retry</button>
        </div>
      )}
      {data && !hasRules && !hasRefs && (
        <p className="text-sm text-gray-400">
          No IOCs or techniques to turn into detections yet. Import a bundle or ingest more
          documents and come back.
        </p>
      )}
      {(hasRules || hasRefs) && (
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-gray-500">
            {data!.count > 0 ? `${data!.count} IOC rule(s)` : 'No IOC rules'}
            {hasRefs ? ` · ${data!.references.length} SigmaHQ reference(s)` : ''}
          </span>
          <button className="btn btn-secondary btn-sm" onClick={downloadAll} disabled={downloading}>
            {downloading ? 'Preparing...' : 'Download all (.zip)'}
          </button>
        </div>
      )}
      {hasRules && (
        <div className="flex gap-4">
          <ul className="w-1/3 space-y-1 text-sm max-h-96 overflow-auto">
            {data!.rules.map((rule: SigmaRule) => (
              <li key={rule.id}>
                <button
                  className={`w-full text-left px-2 py-1 rounded ${selected === rule.id ? 'bg-gray-700' : 'hover:bg-gray-800'}`}
                  onClick={() => setSelected(rule.id)}
                >
                  <div className="flex items-center gap-2">
                    <span className={`mono text-xs px-1.5 py-0.5 rounded ${LEVEL_TONE[rule.level] ?? 'bg-gray-700'}`}>
                      {rule.level}
                    </span>
                    <span className="truncate">{rule.title}</span>
                  </div>
                  <div className="text-xs text-gray-500 mt-0.5">{rule.logsource.category} / {rule.logsource.product}</div>
                </button>
              </li>
            ))}
          </ul>
          <div className="flex-1">
            {selected ? (
              <RulePreview rule={data!.rules.find((r: SigmaRule) => r.id === selected)!} />
            ) : (
              <p className="text-sm text-gray-500">Pick a rule to see the YAML.</p>
            )}
          </div>
        </div>
      )}
      {hasRefs && <ReferencesSection references={data!.references} />}
    </Card>
  )
}

function ReferencesSection({ references }: { references: SigmaHqReference[] }) {
  const covered = references.filter((r) => r.count > 0)
  const gaps = references.filter((r) => r.count === 0)
  return (
    <div className="mt-4 border-t border-gray-800 pt-3">
      <h4 className="text-sm font-semibold text-gray-300 mb-1">SigmaHQ references</h4>
      <p className="text-xs text-gray-500 mb-2">
        Existing community-vetted rules per observed technique &mdash; {covered.length} covered,
        {' '}{gaps.length} with no rule yet. Deploy these rather than a generated placeholder.
      </p>
      <div className="space-y-0.5 text-sm max-h-96 overflow-auto">
        {covered.map((r: SigmaHqReference) => (
          <details key={r.technique_id} className="rounded hover:bg-gray-800/40">
            <summary className="cursor-pointer px-2 py-1 flex items-center gap-2">
              <span className="mono text-xs text-gray-400">{r.technique_id}</span>
              <span className="flex-1 truncate">{r.technique_name}</span>
              <span className="text-xs px-1.5 py-0.5 rounded bg-sky-900/60 text-sky-200">{r.count}</span>
            </summary>
            <ul className="pl-7 pb-1 space-y-0.5">
              {r.rules.map((rule: SigmaHqRule) => (
                <li key={rule.url}>
                  <a href={rule.url} target="_blank" rel="noopener noreferrer" className="text-sky-400 hover:underline">
                    {rule.title}
                  </a>
                </li>
              ))}
              {r.count > r.rules.length && (
                <li>
                  <a href={r.browse_url} target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:underline">
                    ...and {r.count - r.rules.length} more on GitHub
                  </a>
                </li>
              )}
            </ul>
          </details>
        ))}
        {gaps.length > 0 && (
          <p className="px-2 py-1 text-xs text-gray-500">
            No SigmaHQ rule yet (coverage gap): {gaps.map((r) => r.technique_id).join(', ')}
          </p>
        )}
      </div>
    </div>
  )
}

function RulePreview({ rule }: { rule: SigmaRule }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    const text = rule.yaml
    let ok = false
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text)
        ok = true
      }
    } catch {
      // secure-context write failed; fall through to the textarea fallback below
    }
    if (!ok) {
      // Insecure context (the app served over plain http on a LAN IP): the Clipboard API is
      // unavailable there, so fall back to a hidden textarea + execCommand, which still works.
      try {
        const ta = document.createElement('textarea')
        ta.value = text
        ta.style.position = 'fixed'
        ta.style.opacity = '0'
        document.body.appendChild(ta)
        ta.focus()
        ta.select()
        ok = document.execCommand('copy')
        document.body.removeChild(ta)
      } catch {
        ok = false
      }
    }
    if (ok) {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }
  }
  const download = () => {
    const blob = new Blob([rule.yaml + '\n'], { type: 'application/x-yaml' })
    const url = URL.createObjectURL(blob)
    const safe = rule.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80)
    const a = document.createElement('a')
    a.href = url
    a.download = `${safe || rule.id}.yml`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }
  return (
    <div>
      <div className="flex gap-2 mb-2">
        <button className="btn btn-secondary btn-sm" onClick={copy}>{copied ? 'Copied' : 'Copy YAML'}</button>
        <button className="btn btn-secondary btn-sm" onClick={download}>Download .yml</button>
      </div>
      <pre className="mono text-xs bg-black/40 p-3 rounded max-h-80 overflow-auto whitespace-pre">
        {rule.yaml}
      </pre>
    </div>
  )
}
