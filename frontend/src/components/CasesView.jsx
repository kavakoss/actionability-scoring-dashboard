import { useEffect, useState } from 'react'
import { fetchCases } from '../api'
import { EmptyState, LevelBadge, Meter, Panel, SectionTitle, TechniqueTag, levelTone, shortId } from './ui'

const TECH_LABELS = {
  'T1059.001': 'PowerShell',
  'T1059.003': 'CMD',
  'T1105': 'Ingress Transfer',
}

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
          <div className="flex items-center gap-2">
            <select
              value={filters.technique}
              onChange={update('technique')}
              className="rounded border border-edge bg-raised px-2 py-1 text-xs text-ink outline-none focus:border-accent"
            >
              <option value="">All techniques</option>
              <option value="T1059.001">T1059.001 PowerShell</option>
              <option value="T1059.003">T1059.003 CMD</option>
              <option value="T1105">T1105 Ingress Transfer</option>
            </select>
            <select
              value={filters.level}
              onChange={update('level')}
              className="rounded border border-edge bg-raised px-2 py-1 text-xs text-ink outline-none focus:border-accent"
            >
              <option value="">All levels</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
            <span className="w-16 text-right text-2xs text-ink-faint">
              {cases ? `${cases.length} cases` : 'loading…'}
            </span>
          </div>
        }
      >
        Correlated cases
      </SectionTitle>

      {cases && cases.length === 0 && (
        <EmptyState title="No cases match the filters" hint="Try a different technique or level." />
      )}

      {cases && cases.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-edge text-2xs uppercase tracking-wider text-ink-faint">
                <th className="px-4 py-2 font-medium">Seed</th>
                <th className="px-4 py-2 font-medium">Host</th>
                <th className="px-4 py-2 font-medium">Technique</th>
                <th className="px-4 py-2 font-medium">Time</th>
                <th className="px-4 py-2 font-medium">Case score</th>
                <th className="px-4 py-2 font-medium">Level</th>
                <th className="px-4 py-2 font-medium">Required</th>
                <th className="px-4 py-2 font-medium">Events</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((item) => (
                <tr key={item.case_id} className="row-link cursor-pointer" onClick={() => onSelect(item.case_id)}>
                  <td className="px-4 py-2.5">
                    <div className="text-xs text-ink">{item.seed?.rule?.description || 'Seed alert'}</div>
                    <div className="font-mono text-2xs text-ink-faint">{shortId(item.case_id, 26)}</div>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-ink-muted">{item.seed?.agent || '-'}</td>
                  <td className="px-4 py-2.5">
                    <TechniqueTag technique={item.technique} label={TECH_LABELS[item.technique] || item.technique} />
                  </td>
                  <td className="tabular px-4 py-2.5 text-xs text-ink-muted">{formatTime(item.seed?.timestamp)}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <span className="tabular w-10 text-sm font-semibold text-ink">{item.case_score}</span>
                      <Meter value={item.case_score} tone={levelTone(item.level)} className="w-24" />
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <LevelBadge level={item.level} />
                  </td>
                  <td className="tabular px-4 py-2.5 text-xs text-ink-muted">
                    {(item.required_coverage * 100).toFixed(0)}%
                  </td>
                  <td className="tabular px-4 py-2.5 text-xs text-ink-muted">
                    {item.nodes}n / {item.edges}e
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
