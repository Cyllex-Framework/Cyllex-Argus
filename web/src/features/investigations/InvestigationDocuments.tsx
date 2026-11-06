import { Link } from 'react-router-dom'
import type { DocumentSummary } from '../../api/types'
import { StagePill } from '../../components/badges'
import { formatDate } from '../../lib/format'

/** The documents an investigation collected, with their pipeline stage. Shared by the detail page and the dashboard. */
export function InvestigationDocuments({ documents }: { documents: DocumentSummary[] }) {
  if (documents.length === 0) return <p className="text-sm text-gray-400">No documents recorded for this investigation.</p>
  return (
    <table className="data-table w-full">
      <thead><tr><th>Title</th><th>Publisher</th><th>Stage</th><th>Published</th></tr></thead>
      <tbody>
        {documents.map((doc) => (
          <tr key={doc.id}>
            <td><Link to={`/documents/${doc.id}`} className="text-purple-400 hover:underline">{doc.title}</Link></td>
            <td className="text-gray-400">{doc.publisher}</td>
            <td><StagePill stage={doc.stage} /></td>
            <td className="text-xs text-gray-400">{formatDate(doc.published_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
