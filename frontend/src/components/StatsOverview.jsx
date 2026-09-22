import { Panel } from './ui'

const LEVEL_TONE = {
  Low: 'text-sev-low',
  Medium: 'text-sev-medium',
  High: 'text-sev-high',
}

const TECH_LABEL = {
  'T1059.001': 'PowerShell',
  'T1059.003': 'CMD',
  'T1105': 'Ingress Transfer',
}

function Tile({ label, value, hint, valueClass = 'text-ink' }) {
  return (
    <Panel className="px-4 py-3">
      <p className="text-2xs uppercase tracking-wider text-ink-faint">{label}</p>
      <p className={`tabular mt-1 text-2xl font-semibold ${valueClass}`}>{value}</p>
      {hint && <p className="mt-0.5 text-2xs text-ink-faint">{hint}</p>}
    </Panel>
  )
}

export default function StatsOverview({ stats }) {
  if (!stats) return null

  const { total_alerts, by_level = {}, by_technique = {} } = stats

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
      <Tile label="Alerts" value={total_alerts} hint="scored events" />
      {['High', 'Medium', 'Low'].map((level) => (
        <Tile
          key={level}
          label={`${level} actionability`}
          value={by_level[level] ?? 0}
          hint={total_alerts ? `${Math.round(((by_level[level] ?? 0) / total_alerts) * 100)}% of total` : '-'}
          valueClass={LEVEL_TONE[level]}
        />
      ))}
      {Object.entries(by_technique).map(([technique, data]) => (
        <Tile
          key={technique}
          label={TECH_LABEL[technique] || technique}
          value={data.avg_percentage != null ? `${data.avg_percentage}%` : data.avg_score}
          hint={`${data.count} alerts · avg`}
        />
      ))}
    </div>
  )
}
