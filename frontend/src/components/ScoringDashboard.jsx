import { Badge, EmptyState, LevelBadge, Meter, Panel, SectionTitle, TechniqueTag, levelTone } from './ui'

const TECH_LABELS = {
  'T1059.001': 'PowerShell',
  'T1059.003': 'CMD',
  'T1105': 'Ingress Transfer',
}

function formatTime(value) {
  if (!value) return '-'
  try {
    return new Date(value).toLocaleString(undefined, {
      year: 'numeric',
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
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label="Filter alerts by technique"
              value={filters.technique || ''}
              onChange={(event) => onFilter('technique', event.target.value)}
              className="rounded-lg border border-edge bg-panel px-3 py-2 text-sm text-ink outline-none focus:border-accent"
            >
              <option value="">All techniques</option>
              <option value="T1059.001">T1059.001 PowerShell</option>
              <option value="T1059.003">T1059.003 CMD</option>
              <option value="T1105">T1105 Ingress Transfer</option>
            </select>
            <select
              aria-label="Filter alerts by actionability"
              value={filters.level || ''}
              onChange={(event) => onFilter('level', event.target.value)}
              className="rounded-lg border border-edge bg-panel px-3 py-2 text-sm text-ink outline-none focus:border-accent"
            >
              <option value="">All levels</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        }
      >
        Alert actionability
      </SectionTitle>

      {alerts.length === 0 && <EmptyState title="No alerts match the filters" />}

      {alerts.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-edge bg-raised/60 text-xs text-ink-muted">
                <th className="whitespace-nowrap px-5 py-3 font-semibold">Observed</th>
                <th className="px-4 py-3 font-semibold">Endpoint</th>
                <th className="px-4 py-3 font-semibold">ATT&CK technique</th>
                <th className="px-4 py-3 font-semibold">Detection rule</th>
                <th className="px-4 py-3 font-semibold">Actionability</th>
                <th className="px-4 py-3 font-semibold">Wazuh rule level</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => {
                const scoring = alert.scoring || {}
                const mitre = alert.mitre || {}
                return (
                  <tr key={alert.id} className="row-link cursor-pointer" onClick={() => onSelect(alert.id)}>
                    <td className="tabular whitespace-nowrap px-5 py-3 text-xs text-ink-muted">{formatTime(alert.timestamp)}</td>
                    <td className="px-4 py-3 text-sm font-medium text-ink">{alert.agent}</td>
                    <td className="px-4 py-3">
                      <TechniqueTag
                        technique={mitre.technique}
                        label={TECH_LABELS[mitre.technique] || mitre.technique || 'Unknown'}
                      />
                    </td>
                    <td className="max-w-[320px] truncate px-4 py-3 text-sm text-ink-muted" title={alert.rule?.description || ''}>
                      {alert.rule?.description || '-'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="tabular whitespace-nowrap text-sm font-semibold text-ink">
                          {scoring.total_score}/100
                        </span>
                        <Meter value={scoring.percentage || 0} tone={levelTone(scoring.level)} className="w-16" />
                        <LevelBadge level={scoring.level} />
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <Badge className="border-edge bg-raised text-ink-muted">L{alert.rule?.level ?? '-'}</Badge>
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
