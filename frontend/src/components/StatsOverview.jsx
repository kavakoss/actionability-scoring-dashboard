import { Meter, Panel, SectionTitle, TechniqueTag, levelTone } from './ui'

const TECH_LABEL = {
  'T1059.001': 'PowerShell',
  'T1059.003': 'Windows Command Shell',
  T1105: 'Ingress Tool Transfer',
}

const LEVEL_TONE = {
  High: 'text-band-high',
  Medium: 'text-band-medium',
  Low: 'text-band-low',
}

function Metric({ label, value, detail, tone = 'text-ink' }) {
  return (
    <div className="rounded-lg border border-edge/70 bg-raised/60 p-4">
      <p className="text-sm font-medium text-ink-muted">{label}</p>
      <p className={`tabular mt-2 text-3xl font-semibold tracking-tight ${tone}`}>{value}</p>
      <p className="mt-1 text-xs text-ink-faint">{detail}</p>
    </div>
  )
}

export default function StatsOverview({ stats }) {
  if (!stats) return null

  const { total_alerts = 0, by_level = {}, by_technique = {} } = stats

  return (
    <div className="space-y-5">
      <Panel className="p-5 md:p-6">
        <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold tracking-tight text-ink">Actionability overview</h2>
            <p className="mt-1 max-w-2xl text-sm text-ink-muted">
              AHP-weighted telemetry completeness. These scores describe evidence quality, not threat severity.
            </p>
          </div>
          <span className="rounded-full bg-raised px-3 py-1.5 text-xs font-medium text-ink-muted">
            {total_alerts} alerts analyzed
          </span>
        </div>

        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Metric label="Alerts analyzed" value={total_alerts} detail="Current source and study window" />
          {['High', 'Medium', 'Low'].map((level) => {
            const value = by_level[level] ?? 0
            const share = total_alerts ? Math.round((value / total_alerts) * 100) : 0
            return (
              <Metric
                key={level}
                label={`${level} actionability`}
                value={value}
                detail={`${share}% of analyzed alerts`}
                tone={LEVEL_TONE[level]}
              />
            )
          })}
        </div>
      </Panel>

      <Panel>
        <SectionTitle right={<span className="text-xs text-ink-muted">Mean normalized AHP score</span>}>
          Technique coverage
        </SectionTitle>
        <div className="grid gap-4 p-5 md:grid-cols-3">
          {Object.entries(by_technique).map(([technique, data]) => {
            const score = data.avg_percentage ?? data.avg_score ?? 0
            return (
              <div key={technique} className="rounded-lg border border-edge p-4">
                <TechniqueTag technique={technique} label={`${technique} · ${TECH_LABEL[technique] || technique}`} />
                <div className="mt-4 flex items-baseline justify-between gap-3">
                  <span className="tabular text-2xl font-semibold tracking-tight text-ink">{score}%</span>
                  <span className="text-xs text-ink-muted">
                    {data.count} {data.count === 1 ? 'alert' : 'alerts'}
                  </span>
                </div>
                <Meter value={score} tone={levelTone(score > 50 ? 'High' : score >= 25 ? 'Medium' : 'Low')} className="mt-2" />
                <p className="mt-2 text-xs text-ink-faint">Average expected-field completeness</p>
              </div>
            )
          })}
          {Object.keys(by_technique).length === 0 && (
            <p className="text-sm text-ink-muted">No technique-mapped alerts in this view.</p>
          )}
        </div>
      </Panel>
    </div>
  )
}
