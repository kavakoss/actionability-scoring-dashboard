import { useEffect, useState } from 'react'
import { fetchCases } from '../api'
import { EmptyState, Meter, Panel, SectionTitle, SkeletonRows, TechniqueTag, levelTone, shortId } from './ui'

const TECH_LABELS = {
  'T1059.001': 'PowerShell',
  'T1059.003': 'CMD',
  'T1105': 'Ingress Transfer',
}

const BAND_TEXT = {
  High: 'text-band-high',
  Medium: 'text-band-medium',
  Low: 'text-band-low',
}

const bandText = (level) => BAND_TEXT[level] || 'text-ink'

function formatTime(value) {
  if (!value) return '-'
  return new Date(value).toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export default function CasesView({ onSelect }) {
  const [cases, setCases] = useState(null)
  const [filters, setFilters] = useState({ technique: '', level: '' })

  useEffect(() => {
    const params = {}
    if (filters.technique) params.technique = filters.technique
    if (filters.level) params.level = filters.level
    setCases(null)
    fetchCases(params)
      .then((data) => setCases(data.cases || []))
      .catch(() => setCases([]))
  }, [filters])

  const update = (key) => (event) => setFilters((prev) => ({ ...prev, [key]: event.target.value }))

  return (
    <Panel>
      <SectionTitle
        right={
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label="Filter cases by technique"
              value={filters.technique}
              onChange={update('technique')}
              className="rounded-lg border border-edge bg-panel px-3 py-2 text-sm text-ink outline-none focus:border-accent"
            >
              <option value="">All techniques</option>
              <option value="T1059.001">T1059.001 PowerShell</option>
              <option value="T1059.003">T1059.003 CMD</option>
              <option value="T1105">T1105 Ingress Transfer</option>
            </select>
            <select
              aria-label="Filter cases by actionability"
              value={filters.level}
              onChange={update('level')}
              className="rounded-lg border border-edge bg-panel px-3 py-2 text-sm text-ink outline-none focus:border-accent"
            >
              <option value="">All levels</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
            <span className="min-w-16 text-right text-xs text-ink-muted">
              {cases ? `${cases.length} cases` : 'loading…'}
            </span>
          </div>
        }
      >
        Correlated cases
      </SectionTitle>

      {cases === null && <SkeletonRows rows={6} />}

      {cases && cases.length === 0 && (
        <EmptyState title="No cases match the filters" hint="Try a different technique or level." />
      )}

      {cases && cases.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-edge bg-raised/60 text-xs text-ink-muted">
                <th className="px-5 py-3 font-semibold">Seed alert</th>
                <th className="px-4 py-3 font-semibold">Endpoint</th>
                <th className="px-4 py-3 font-semibold">ATT&CK technique</th>
                <th className="px-4 py-3 font-semibold">Observed</th>
                <th className="px-4 py-3 font-semibold">Case actionability</th>
                <th className="px-4 py-3 font-semibold">Wazuh level</th>
                <th className="px-4 py-3 font-semibold">Evidence coverage</th>
                <th className="px-4 py-3 font-semibold">Telemetry</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((item) => (
                <tr key={item.case_id} className="row-link cursor-pointer" onClick={() => onSelect(item.case_id)}>
                  <td className="max-w-[320px] px-5 py-3">
                    <div className="truncate text-sm font-medium text-ink" title={item.seed?.rule?.description || 'Seed alert'}>
                      {item.seed?.rule?.description || 'Seed alert'}
                    </div>
                    <div className="mt-1 font-mono text-xs text-ink-faint">{shortId(item.case_id, 26)}</div>
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-sm font-medium text-ink-muted">
                    {item.seed?.agent || '-'}
                  </td>
                  <td className="px-4 py-3">
                    <TechniqueTag technique={item.technique} label={TECH_LABELS[item.technique] || item.technique} />
                  </td>
                  <td className="tabular whitespace-nowrap px-4 py-3 text-sm text-ink-muted">{formatTime(item.seed?.timestamp)}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className={`tabular whitespace-nowrap text-sm font-semibold ${bandText(item.level)}`}>
                        {item.case_score}/100
                      </span>
                      <Meter value={item.case_score} tone={levelTone(item.level)} className="w-16" />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded-md border border-edge bg-raised px-2 py-1 text-xs font-medium text-ink-muted">
                      L{item.seed?.rule?.level ?? '-'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Meter value={item.required_coverage * 100} tone="bg-accent" className="w-16" />
                      <span className="tabular text-sm text-ink-muted">{(item.required_coverage * 100).toFixed(0)}%</span>
                    </div>
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-sm text-ink-muted">
                    {item.nodes} {item.nodes === 1 ? 'event' : 'events'} · {item.edges}{' '}
                    {item.edges === 1 ? 'relation' : 'relations'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}
