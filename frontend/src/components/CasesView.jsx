import { useEffect, useState } from 'react'
import { fetchCases } from '../api'
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
  shortId,
} from './ui'

export default function CasesView({ onSelect }) {
  const [cases, setCases] = useState(null)
  const [error, setError] = useState(null)
  const [filters, setFilters] = useState({ technique: '', level: '' })
  useEffect(() => {
    let active = true
    setCases(null)
    setError(null)
    fetchCases(
      Object.fromEntries(Object.entries(filters).filter(([, value]) => value)),
    )
      .then((data) => {
        if (active) setCases(data.cases || [])
      })
      .catch(() => {
        if (active) setError('Unable to load cases. Check the API connection.')
      })
    return () => {
      active = false
    }
  }, [filters])
  return (
    <div className="space-y-6">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Investigation workspace</p>
          <h1 className="mt-2 text-display font-semibold">Correlated cases</h1>
          <p className="mt-2 text-body text-ink-muted">
            From a seed alert to the evidence needed to investigate.
          </p>
        </div>
        <p className="text-small text-ink-muted">
          <strong className="mr-2 text-title font-medium text-ink">
            {cases?.length ?? '—'}
          </strong>
          cases in view
        </p>
      </div>
      <Panel>
        <SectionTitle
          right={
            <Filters
              kind="cases"
              filters={filters}
              onChange={(key, value) =>
                setFilters((prev) => ({ ...prev, [key]: value }))
              }
            />
          }
        >
          Case inventory
        </SectionTitle>
        {error ? (
          <EmptyState title="Cases unavailable" hint={error} />
        ) : cases === null ? (
          <SkeletonRows rows={6} />
        ) : !cases.length ? (
          <EmptyState
            title="No cases match these filters"
            hint="Choose another technique or actionability band."
          />
        ) : (
          <div className="table-scroll">
            <table
              className="data-table min-w-[1136px]"
              aria-label="Correlated cases"
            >
              <colgroup>
                {[23, 12, 13, 11, 15, 7, 8, 11].map((width, i) => (
                  <col key={i} style={{ width: `${width}%` }} />
                ))}
              </colgroup>
              <thead>
                <tr>
                  <th>Seed alert</th>
                  <th>Endpoint</th>
                  <th>ATT&amp;CK technique</th>
                  <th>Observed · UTC</th>
                  <th className="numeric">Actionability</th>
                  <th className="numeric">Wazuh</th>
                  <th className="numeric">Coverage</th>
                  <th className="numeric">Telemetry</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((item) => (
                  <tr
                    key={item.case_id}
                    className="row-link cursor-pointer"
                    onClick={() => onSelect(item.case_id)}
                  >
                    <td>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          onSelect(item.case_id)
                        }}
                        className="table-title"
                        title={item.seed?.rule?.description || 'Seed alert'}
                      >
                        {item.seed?.rule?.description?.trim() || 'Seed alert'}
                      </button>
                      <p
                        className="mt-1 truncate font-mono text-caption text-ink-faint"
                        title={item.case_id}
                      >
                        {shortId(item.case_id, 30)}
                      </p>
                    </td>
                    <td className="text-ink-muted">
                      <span className="block truncate" title={item.seed?.agent}>
                        {item.seed?.agent || '—'}
                      </span>
                    </td>
                    <td>
                      <TechniqueTag
                        technique={item.technique}
                        label={TECH_LABELS[item.technique] || item.technique}
                      />
                      <p className="mt-1 pl-3.5 font-mono text-caption text-ink-faint">
                        {item.technique}
                      </p>
                    </td>
                    <td className="text-caption text-ink-muted">
                      <time dateTime={item.seed?.timestamp}>
                        {formatTime(item.seed?.timestamp).split(', ')[0]}
                        <br />
                        {formatTime(item.seed?.timestamp, true)}
                      </time>
                    </td>
                    <td>
                      <ScoreCell score={item.case_score} level={item.level} />
                    </td>
                    <td className="numeric">
                      <WazuhBadge level={item.seed?.rule?.level} />
                    </td>
                    <td className="numeric">
                      <span className="font-medium">
                        {(item.required_coverage * 100).toFixed(0)}%
                      </span>
                      <p className="mt-1 text-caption text-ink-faint">
                        required
                      </p>
                    </td>
                    <td className="numeric text-ink-muted">
                      {item.nodes} events
                      <p className="mt-1 text-caption text-ink-faint">
                        {item.edges} relations
                      </p>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="flex flex-wrap justify-between gap-2 border-t border-edge px-5 py-3 text-caption text-ink-faint">
          <span>Select a seed alert to inspect its case.</span>
          <span>High actionability = more complete evidence</span>
        </div>
      </Panel>
    </div>
  )
}
