import { EmptyState, LevelBadge, Meter, Panel, SectionTitle, TechniqueTag, levelTone } from './ui'

const TECH_LABELS = {
  'T1059.001': 'PowerShell',
  'T1059.003': 'CMD',
  'T1105': 'Ingress Transfer',
}

function formatTime(value) {
  if (!value) return '-'
  try {
    return new Date(value).toLocaleString(undefined, {
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return value
  }
}

export default function ScoringDashboard({ alerts, filters, onFilter, onSelect }) {
  return (
    <Panel>
      <SectionTitle
        right={
          <div className="flex items-center gap-2">
            <select
              value={filters.technique || ''}
              onChange={(event) => onFilter('technique', event.target.value)}
              className="rounded border border-edge bg-raised px-2 py-1 text-xs text-ink outline-none focus:border-accent"
            >
              <option value="">All techniques</option>
              <option value="T1059.001">T1059.001 PowerShell</option>
              <option value="T1059.003">T1059.003 CMD</option>
              <option value="T1105">T1105 Ingress Transfer</option>
            </select>
            <select
              value={filters.level || ''}
              onChange={(event) => onFilter('level', event.target.value)}
              className="rounded border border-edge bg-raised px-2 py-1 text-xs text-ink outline-none focus:border-accent"
            >
              <option value="">All levels</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        }
      >
        Alerts
      </SectionTitle>

      {alerts.length === 0 && <EmptyState title="No alerts match the filters" />}

      {alerts.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-edge text-2xs uppercase tracking-wider text-ink-faint">
                <th className="px-4 py-2 font-medium">Time</th>
                <th className="px-4 py-2 font-medium">Host</th>
                <th className="px-4 py-2 font-medium">Technique</th>
                <th className="px-4 py-2 font-medium">Rule</th>
                <th className="px-4 py-2 font-medium">Alert score</th>
                <th className="px-4 py-2 font-medium">Level</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => {
                const scoring = alert.scoring || {}
                const mitre = alert.mitre || {}
                return (
                  <tr key={alert.id} className="row-link cursor-pointer" onClick={() => onSelect(alert.id)}>
                    <td className="tabular px-4 py-2.5 font-mono text-2xs text-ink-muted">{formatTime(alert.timestamp)}</td>
                    <td className="px-4 py-2.5 text-xs text-ink">{alert.agent}</td>
                    <td className="px-4 py-2.5">
                      <TechniqueTag
                        technique={mitre.technique}
                        label={TECH_LABELS[mitre.technique] || mitre.technique || 'Unknown'}
                      />
                    </td>
                    <td className="max-w-[280px] truncate px-4 py-2.5 text-xs text-ink-muted">
                      {alert.rule?.description || '-'}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        <span className="tabular w-10 text-sm font-semibold text-ink">{scoring.total_score}</span>
                        <Meter value={scoring.percentage || 0} tone={levelTone(scoring.level)} className="w-24" />
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <LevelBadge level={scoring.level} />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}
