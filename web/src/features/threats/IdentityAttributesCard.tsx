import { useState } from 'react'
import { useSetIdentityAttributes } from '../../api/hooks'
import { Card } from '../../components/Card'

/** Form shown on an identity entity's threat profile to tag it with sector and country.
 * Those keys drive the `/query/targets` page and the `argus query-targets` CLI. */
export function IdentityAttributesCard({
  entityId,
  attributes,
}: { entityId: string; attributes: Record<string, string> }) {
  const [sector, setSector] = useState(attributes.sector ?? '')
  const [country, setCountry] = useState(attributes.country ?? '')
  const [saved, setSaved] = useState<string | null>(null)
  const save = useSetIdentityAttributes()

  const submit = () => {
    setSaved(null)
    save.mutate(
      { id: entityId, attrs: { sector: sector.trim() || undefined, country: country.trim() || undefined } },
      { onSuccess: (result) => setSaved(
        `Saved: sector=${result.attributes.sector ?? '-'}, country=${result.attributes.country ?? '-'}`,
      ) },
    )
  }

  return (
    <Card title="Identity attributes">
      <p className="text-xs text-gray-400 mb-3">
        Tag this identity with its sector and country so it shows up on the Query page when
        operators ask "who targets financial-services in US?". Leave empty to clear a value.
      </p>
      <div className="flex flex-col gap-2">
        <label className="text-xs text-gray-400 flex flex-col">
          Sector (free-text, lowercase recommended)
          <input className="input" value={sector} onChange={(e) => setSector(e.target.value)}
            placeholder="e.g. financial-services" />
        </label>
        <label className="text-xs text-gray-400 flex flex-col">
          Country (ISO 3166 alpha-2)
          <input className="input" value={country} onChange={(e) => setCountry(e.target.value)}
            placeholder="e.g. US" maxLength={10} />
        </label>
        <button
          type="button"
          className="btn btn-primary btn-sm w-fit"
          disabled={save.isPending}
          onClick={submit}
        >
          {save.isPending ? 'Saving…' : 'Save attributes'}
        </button>
        {save.error && <p className="text-sm text-red-400" role="alert">{save.error.message}</p>}
        {saved && <p className="text-sm text-emerald-400" role="status">{saved}</p>}
      </div>
    </Card>
  )
}
