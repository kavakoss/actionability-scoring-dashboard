import {
  EmptyState,
  LevelBadge,
  Meter,
  Panel,
  SkeletonRows,
  TECH_LABELS,
  TechniqueTag,
  levelTone,
} from './ui'

export default function StatsOverview({ stats, error }) {
  if (error)
    return (
      <Panel>
        <EmptyState title="Overview unavailable" hint={error} />
      </Panel>
    )
  if (!stats)
    return (
      <Panel>
        <SkeletonRows rows={3} />
      </Panel>
    )
  const { total_alerts = 0, by_level = {}, by_technique = {} } = stats
  return (
    <div className="space-y-6">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Telemetry assessment</p>
          <h1 className="mt-2 text-display font-semibold">Alert overview</h1>
          <p className="mt-2 text-body text-ink-muted">
            How much of the expected evidence is available for investigation?
          </p>
        </div>
      </div>
      <Panel>
        <div className="grid sm:grid-cols-[1.3fr_2fr]">
          <div className="border-b border-edge p-6 sm:border-b-0 sm:border-r">
            <p className="text-small text-ink-muted">Alerts analyzed</p>
            <p className="mt-2 text-[44px] font-semibold leading-tight tracking-tight">
              {total_alerts}
            </p>
            <p className="mt-2 text-caption text-ink-faint">
              Current source and study window
            </p>
          </div>
          <div className="grid grid-cols-3 divide-x divide-edge py-6">
            {['High', 'Medium', 'Low'].map((level) => {
              const count = by_level[level] ?? 0
              const share = total_alerts
                ? Math.round((count / total_alerts) * 100)
                : 0
              return (
                <div key={level} className="min-w-0 px-4 sm:px-6">
                  <LevelBadge level={level} />
                  <p className="mt-3 text-display font-medium">{count}</p>
                  <p className="mt-2 text-caption text-ink-faint">
                    {share}% of alerts
                  </p>
                  <Meter
                    value={share}
                    tone={levelTone(level)}
                    className="mt-3"
                  />
                </div>
              )
            })}
          </div>
        </div>
        <div className="border-t border-edge px-6 py-3 text-caption text-ink-muted">
          Actionability bands describe evidence completeness. A high score means
          more complete evidence.
        </div>
      </Panel>
      <section aria-label="Technique coverage">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-heading font-semibold">Technique coverage</h2>
          <span className="text-caption text-ink-faint">
            Mean normalized AHP score
          </span>
        </div>
        <div className="grid gap-6 md:grid-cols-3">
          {Object.entries(by_technique).map(([technique, data]) => {
            const score = data.avg_percentage ?? data.avg_score ?? 0
            return (
              <div
                key={technique}
                className="border-l-2 border-edge-strong pl-4"
              >
                <div className="flex flex-wrap justify-between gap-2">
                  <TechniqueTag
                    technique={technique}
                    label={TECH_LABELS[technique] || technique}
                  />
                  <span className="font-mono text-caption text-ink-faint">
                    {technique}
                  </span>
                </div>
                <div className="mb-3 mt-3 flex items-baseline justify-between">
                  <p className="text-title font-medium">
                    {score}
                    <span className="text-small text-ink-faint"> /100</span>
                  </p>
                  <span className="text-caption text-ink-muted">
                    {data.count} alerts
                  </span>
                </div>
                <Meter
                  value={score}
                  tone={levelTone(
                    score > 50 ? 'High' : score >= 25 ? 'Medium' : 'Low',
                  )}
                />
              </div>
            )
          })}
        </div>
      </section>
    </div>
  )
}
