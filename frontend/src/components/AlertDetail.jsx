import { useEffect, useState } from 'react'
import { fetchAlertDetail } from '../api'
import { Dot, KeyValue, LevelBadge, Meter, Panel, SectionTitle, TechniqueTag, levelTone } from './ui'

const TECH_LABELS = {
  'T1059.001': 'PowerShell',
  'T1059.003': 'CMD',
  'T1105': 'Ingress Transfer',
}

const ROLE_TONE = {
  required: 'text-accent border-accent/40',
  supporting: 'text-ink-muted border-edge',
  context: 'text-ink-faint border-edge',
}

function formatTime(value) {
  if (!value) return '-'
  return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' })
}

export default function AlertDetail({ alertId, onBack, onOpenCase }) {
  const [detail, setDetail] = useState(null)

  useEffect(() => {
    setDetail(null)
    fetchAlertDetail(alertId).then(setDetail).catch(() => setDetail(null))
  }, [alertId])

  if (!detail) {
    return <p className="py-10 text-center text-sm text-ink-faint">Loading alert…</p>
  }

  const scoring = detail.scoring
  const mitre = detail.mitre || {}
  const rule = detail.rule || {}
  const expectedFields = Object.values(scoring.categories || {}).flatMap((category) =>
    (category.fields || []).filter((field) => field.expected),
  )
  const presentExpectedFields = expectedFields.filter((field) => field.present).length

  return (
    <div className="space-y-4">
      <button onClick={onBack} className="text-xs text-accent hover:text-blue-400">
        ← Back to alerts
      </button>

      <Panel>
        <div className="flex flex-col gap-5 p-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0 flex-1">
            <TechniqueTag
              technique={mitre.technique}
              label={`${mitre.technique || 'Unknown'} · ${TECH_LABELS[mitre.technique] || mitre.name || '-'}`}
            />
            <h1 className="mt-2 text-base font-semibold text-ink">{rule.description || 'Wazuh alert'}</h1>
            <dl className="mt-4 grid grid-cols-2 gap-x-8 gap-y-3 md:grid-cols-4">
              <KeyValue label="Agent">{detail.agent?.name || '-'}</KeyValue>
              <KeyValue label="Tactic">{mitre.tactic || '-'}</KeyValue>
              <KeyValue label="Rule level" mono>
                {rule.level ?? '-'}
              </KeyValue>
              <KeyValue label="Time" mono>
                <span className="whitespace-nowrap">{formatTime(detail.timestamp)}</span>
              </KeyValue>
            </dl>
          </div>
          <div className="shrink-0 rounded-xl border border-edge bg-raised/60 p-4 lg:w-[300px]">
            <p className="text-xs font-medium text-ink-muted">Actionability score</p>
            <div className="tabular mt-1 text-4xl font-semibold tracking-tight text-ink">
              {scoring.total_score}
              <span className="ml-1 text-lg font-medium text-ink-faint">/100</span>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <LevelBadge level={scoring.level} />
              <span className="text-xs text-ink-muted">AHP band</span>
            </div>
            <div className="mt-3 flex items-center justify-between gap-4 text-xs">
              <span className="text-ink-muted">Expected fields present</span>
              <span className="tabular font-semibold text-ink">{presentExpectedFields}/{expectedFields.length}</span>
            </div>
            <p className="mt-3 text-xs leading-5 text-ink-muted">
              ATT&CK selects the telemetry profile. The score measures field completeness—not threat severity or an ATT&CK rating.
            </p>
            <p className="mt-2 text-xs text-ink-faint">Profile: {scoring.profile_name}</p>
            <button
              onClick={() => onOpenCase(alertId)}
              className="mt-3 rounded-lg border border-edge bg-panel px-3 py-2 text-xs font-medium text-ink-muted transition-colors hover:border-accent hover:text-accent"
            >
              Open correlated case
            </button>
          </div>
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {Object.entries(scoring.categories || {}).map(([key, category]) => (
          <Panel key={key}>
            <SectionTitle
              right={
                <span className="tabular text-2xs text-ink-muted">
                  {category.applicable ? `${category.score.toFixed(2)} / ${category.max.toFixed(2)}` : 'n/a'}
                </span>
              }
            >
              {category.label}
            </SectionTitle>
            <div className="px-5 pt-4">
              <Meter
                value={category.applicable ? category.percentage : 0}
                tone={levelTone(scoring.level)}
              />
            </div>
            <ul className="divide-y divide-edge/70 px-5 pb-4 pt-2">
              {category.fields?.map((field) => (
                <li key={field.field} className={`py-2 ${field.expected ? '' : 'opacity-45'}`}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex min-w-0 items-start gap-2">
                      <span className="mt-1">
                        <Dot on={field.present} tone={field.present ? 'bg-accent' : 'bg-edge'} />
                      </span>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-ink">{field.label}</span>
                          {field.expected && (
                            <span
                              className={`rounded border px-1 text-2xs ${
                                ROLE_TONE[field.role] || ROLE_TONE.context
                              }`}
                            >
                              {field.role}
                            </span>
                          )}
                        </div>
                        <div className="mt-0.5 truncate font-mono text-2xs text-ink-faint" title={field.value || ''}>
                          {field.present ? field.value : 'missing'}
                        </div>
                        <div className="mt-0.5 text-2xs text-ink-faint">{field.mitre_component}</div>
                      </div>
                    </div>
                    <span className="tabular shrink-0 text-2xs text-ink-faint">{field.weight.toFixed(3)}</span>
                  </div>
                </li>
              ))}
            </ul>
          </Panel>
        ))}
      </div>
    </div>
  )
}
