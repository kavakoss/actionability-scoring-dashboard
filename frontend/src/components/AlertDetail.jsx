import { useEffect, useState } from 'react'
import { fetchAlertDetail } from '../api'
import {
  Dot,
  EmptyState,
  KeyValue,
  Meter,
  Panel,
  ScoreCard,
  SectionTitle,
  SkeletonRows,
  TECH_LABELS,
  TechniqueTag,
  WazuhBadge,
  formatTime,
  levelTone,
} from './ui'

export default function AlertDetail({ alertId, onBack, onOpenCase }) {
  const [detail, setDetail] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => {
    let active = true
    setDetail(null)
    setError(null)
    fetchAlertDetail(alertId)
      .then((data) => {
        if (active) setDetail(data)
      })
      .catch(() => {
        if (active) setError('The requested alert could not be loaded.')
      })
    return () => {
      active = false
    }
  }, [alertId])
  const back = (
    <button onClick={onBack} className="text-link">
      ← Back to alerts
    </button>
  )
  if (error)
    return (
      <div>
        {back}
        <Panel className="mt-5">
          <EmptyState title="Alert unavailable" hint={error} />
        </Panel>
      </div>
    )
  if (!detail)
    return (
      <div>
        {back}
        <Panel className="mt-5">
          <SkeletonRows rows={6} />
        </Panel>
      </div>
    )
  const { scoring, mitre = {}, rule = {} } = detail
  const expectedFields = Object.values(scoring.categories || {}).flatMap(
    (category) => (category.fields || []).filter((field) => field.expected),
  )
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        {back}
        <button className="control" onClick={() => onOpenCase(alertId)}>
          Open correlated case ↗
        </button>
      </div>
      <Panel className="overflow-hidden">
        <div className="flex flex-col lg:flex-row">
          <div className="min-w-0 flex-1 p-6">
            <p className="eyebrow">Alert assessment</p>
            <div className="mt-3">
              <TechniqueTag
                technique={mitre.technique}
                label={`${mitre.technique || 'Unknown'} · ${TECH_LABELS[mitre.technique] || mitre.name || 'Unmapped'}`}
              />
            </div>
            <h1
              className="mt-3 line-clamp-2 break-words text-title font-semibold"
              title={rule.description}
            >
              {rule.description?.trim() || 'Wazuh alert'}
            </h1>
            <details className="mt-2 text-caption">
              <summary className="cursor-pointer text-ink-muted">
                Full rule description and alert ID
              </summary>
              <p className="mono-value mt-3">{rule.description}</p>
              <p className="mono-value mt-2">{alertId}</p>
            </details>
            <dl className="mt-6 grid grid-cols-2 gap-x-6 gap-y-5 sm:grid-cols-3">
              <KeyValue label="Endpoint">{detail.agent?.name || '—'}</KeyValue>
              <KeyValue label="ATT&CK tactic">{mitre.tactic || '—'}</KeyValue>
              <KeyValue label="Wazuh rule level">
                <WazuhBadge level={rule.level} />
              </KeyValue>
              <KeyValue label="Observed · UTC">
                {formatTime(detail.timestamp)}
              </KeyValue>
              <KeyValue label="Rule ID" mono>
                {rule.id || '—'}
              </KeyValue>
              <KeyValue label="Telemetry profile">
                {scoring.profile_name}
              </KeyValue>
            </dl>
          </div>
          <ScoreCard
            label="Alert actionability"
            score={scoring.total_score}
            level={scoring.level}
            covered={expectedFields.filter((f) => f.present).length}
            total={expectedFields.length}
          />
        </div>
      </Panel>
      <div className="page-heading">
        <div>
          <h2 className="text-title font-semibold">Evidence by category</h2>
          <p className="mt-1 text-small text-ink-muted">
            Field presence, values and ATT&amp;CK data components for this
            alert.
          </p>
        </div>
        <span className="text-caption text-ink-faint">
          Field weights are AHP weights
        </span>
      </div>
      <div className="grid items-start gap-5 md:grid-cols-2 xl:grid-cols-3">
        {Object.entries(scoring.categories || {}).map(([key, category]) => {
          const expected = (category.fields || []).filter(
            (field) => field.expected,
          )
          const present = expected.filter((field) => field.present).length
          const band =
            category.percentage > 50
              ? 'High'
              : category.percentage >= 25
                ? 'Medium'
                : 'Low'
          return (
            <Panel key={key}>
              <SectionTitle
                right={
                  <span className="text-small font-medium">
                    {category.applicable
                      ? `${present} / ${expected.length}`
                      : 'N/A'}
                  </span>
                }
              >
                {category.label}
              </SectionTitle>
              <div className="px-5 pt-4">
                <Meter
                  value={category.applicable ? category.percentage : 0}
                  tone={levelTone(band)}
                />
                <p className="mt-2 text-caption text-ink-faint">
                  {category.applicable
                    ? `Expected fields present · weighted score ${category.score.toFixed(2)} / ${category.max.toFixed(2)}`
                    : 'Not expected for this technique'}
                </p>
              </div>
              <ul className="divide-y divide-edge px-5 pb-2 pt-2">
                {category.fields?.map((field) => (
                  <li key={field.field} className="py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <Dot on={field.present} />
                        <span className="text-small font-medium">
                          {field.label}
                        </span>
                      </div>
                      <span className="shrink-0 font-mono text-caption text-ink-faint">
                        {field.weight.toFixed(3)}
                      </span>
                    </div>
                    <div className="my-1.5 flex flex-wrap gap-x-3 text-caption text-ink-faint">
                      <span>{field.present ? 'Present' : 'Missing'}</span>
                      <span>
                        {field.expected ? field.role : 'Not expected'}
                      </span>
                    </div>
                    <p className="mono-value max-h-32 overflow-auto">
                      {field.present ? String(field.value) : '—'}
                    </p>
                    <p className="mt-2 text-caption text-ink-faint">
                      {field.mitre_component}
                    </p>
                  </li>
                ))}
              </ul>
            </Panel>
          )
        })}
      </div>
    </div>
  )
}
