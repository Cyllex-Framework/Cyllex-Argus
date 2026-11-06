import { useRef, useState } from 'react'
import { useImportStix } from '../../api/hooks'
import type { StixImportReport } from '../../api/types'
import { Card } from '../../components/Card'

/** Drag-and-drop surface for ingesting STIX 2.1 bundles produced by MISP, OpenCTI or hand. */
export function StixImportCard() {
  const importStix = useImportStix()
  const [report, setReport] = useState<StixImportReport | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const upload = (file: File) => {
    setReport(null)
    importStix.mutate(file, { onSuccess: setReport })
  }

  return (
    <Card title="Import STIX 2.1">
      <p className="text-xs text-gray-400 mb-4">
        Merge a STIX bundle (JSON) from MISP, OpenCTI or any STIX-aware tool. SDOs become
        entities; attack-patterns dedupe by MITRE external_id. Relationships become claims
        anchored on the uploaded bundle as a document.
      </p>
      <div className="flex items-center gap-3 mb-3">
        <input
          ref={fileRef}
          type="file"
          accept="application/json,.json"
          className="hidden"
          onChange={(event) => {
            const file = event.target.files?.[0]
            if (file) upload(file)
          }}
        />
        <button
          type="button"
          className="btn btn-primary btn-sm"
          disabled={importStix.isPending}
          onClick={() => fileRef.current?.click()}
        >
          {importStix.isPending ? 'Importing…' : 'Choose a bundle (.json)'}
        </button>
      </div>
      {importStix.error && (
        <p className="text-sm text-red-400 mb-3" role="alert">{importStix.error.message}</p>
      )}
      {report && (
        <div className="text-sm text-gray-300 space-y-1">
          <p>Bundle: <code className="mono">{report.bundle_id ?? '(no id)'}</code></p>
          <p>Entities added: <strong>{report.entities_added}</strong>, matched: {report.entities_matched}</p>
          <p>Aliases added: {report.aliases_added}, claims added: {report.claims_added}, identities tagged: {report.identities_tagged}</p>
          {report.skipped.length > 0 && (
            <details>
              <summary className="text-yellow-400 cursor-pointer">
                Skipped {report.skipped.length} item(s)
              </summary>
              <ul className="list-disc pl-6 text-xs text-gray-400">
                {report.skipped.slice(0, 20).map((reason, i) => <li key={i}>{reason}</li>)}
                {report.skipped.length > 20 && (
                  <li className="italic">(+ {report.skipped.length - 20} more)</li>
                )}
              </ul>
            </details>
          )}
        </div>
      )}
    </Card>
  )
}
