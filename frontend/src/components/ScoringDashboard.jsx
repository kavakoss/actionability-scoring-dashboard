import {
  EmptyState,
  Filters,
  Panel,
  ScoreCell,
  SectionTitle,
  SkeletonRows,
  TECH_LABELS,
  TechniqueTag,
  WazuhBadge,
  formatTime,
} from './ui'

export default function ScoringDashboard({
  alerts,
  filters,
  onFilter,
  onSelect,
  error,
}) {
  return (
    <Panel>
      <SectionTitle
        right={<Filters kind="alerts" filters={filters} onChange={onFilter} />}
      >
        Scored alerts{' '}
        <span className="ml-2 text-small font-normal text-ink-faint">
          {alerts?.length ?? '—'}
        </span>
      </SectionTitle>
      {error ? (
        <EmptyState title="Alerts unavailable" hint={error} />
      ) : alerts === null ? (
        <SkeletonRows />
      ) : !alerts.length ? (
        <EmptyState
          title="No alerts match these filters"
          hint="Choose another technique or actionability band."
        />
      ) : (
        <div className="table-scroll">
          <table
            className="data-table min-w-[960px]"
            aria-label="Scored alerts"
          >
            <colgroup>
              {[14, 14, 16, 29, 18, 9].map((width, i) => (
                <col key={i} style={{ width: `${width}%` }} />
              ))}
            </colgroup>
            <thead>
              <tr>
                <th>Observed · UTC</th>
                <th>Endpoint</th>
                <th>ATT&amp;CK technique</th>
                <th>Detection rule</th>
                <th className="numeric">Actionability</th>
                <th className="numeric">Wazuh level</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr
                  key={alert.id}
                  className="row-link cursor-pointer"
                  onClick={() => onSelect(alert.id)}
                >
                  <td className="text-caption text-ink-muted">
                    <time dateTime={alert.timestamp}>
                      {formatTime(alert.timestamp)}
                    </time>
                  </td>
                  <td className="text-ink-muted">
                    <span className="block truncate" title={alert.agent}>
                      {alert.agent}
                    </span>
                  </td>
                  <td>
                    <TechniqueTag
                      technique={alert.mitre?.technique}
                      label={
                        TECH_LABELS[alert.mitre?.technique] ||
                        alert.mitre?.technique
                      }
                    />
                    <p className="mt-1 pl-3.5 font-mono text-caption text-ink-faint">
                      {alert.mitre?.technique}
                    </p>
                  </td>
                  <td>
                    <button
                      className="table-title"
                      title={alert.rule?.description}
                      onClick={(e) => {
                        e.stopPropagation()
                        onSelect(alert.id)
                      }}
                    >
                      {alert.rule?.description?.trim() || 'Wazuh alert'}
                    </button>
                    <span className="mt-1 block font-mono text-caption text-ink-faint">
                      Rule {alert.rule?.id || '—'}
                    </span>
                  </td>
                  <td>
                    <ScoreCell
                      score={alert.scoring?.total_score}
                      level={alert.scoring?.level}
                    />
                  </td>
                  <td className="numeric">
                    <WazuhBadge level={alert.rule?.level} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="border-t border-edge px-5 py-3 text-caption text-ink-faint">
        Select a detection rule to inspect its evidence fields.
      </p>
    </Panel>
  )
}
