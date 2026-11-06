export function StatTile({ label, value, tone = 'text-gray-300' }: { label: string; value: number | string; tone?: string }) {
  return (
    <div className="stat-card">
      <div className={`stat-value ${tone}`}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}
