import { Link } from 'react-router-dom'
import { useInvestigation } from '../../api/hooks'
import { Card } from '../../components/Card'
import { ErrorCard, Loading } from '../../components/QueryState'
import { InvestigationDocuments } from './InvestigationDocuments'

/** The Documents section: the same list as the "Documents & timeline" page, without leaving the dashboard. */
export function DashboardDocuments({ investigationId }: { investigationId: string }) {
  const { data, error, isLoading } = useInvestigation(investigationId)
  return (
    <Card title="Documents"
      actions={<Link to={`/investigations/${investigationId}`} className="text-sm text-purple-400 hover:underline">View documents &amp; timeline →</Link>}>
      {isLoading ? <Loading /> : error || !data ? <ErrorCard error={error} /> : <InvestigationDocuments documents={data.documents} />}
    </Card>
  )
}
