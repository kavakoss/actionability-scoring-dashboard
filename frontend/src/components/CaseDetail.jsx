import { useEffect, useMemo, useState } from 'react'
import { fetchCaseDetail, fetchTimeline } from '../api'
import TimelineView from './TimelineView'
import {
  Dot,
  EmptyState,
  KeyValue,
  LevelBadge,
  Meter,
  Panel,
  SectionTitle,
  TechniqueTag,
  levelTone,
  shortId,
} from './ui'

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

function FactRow({ fact }) {
  const carriers = fact.carriers || []
  const uniqueValues = [...new Set(carriers.map((carrier) => carrier.value))]
  return (
    <tr className="row-link">
      <td className="px-3 py-2">
        <div className="flex items-center gap-2">
          <Dot on={fact.completeness === 1} tone={fact.completeness === 1 ? 'bg-accent' : 'bg-edge'} />
          <span className="text-xs text-ink">{fact.label}</span>
        </div>
        <div className="mt-0.5 pl-4 font-mono text-2xs text-ink-faint">{fact.field}</div>
      </td>
      <td className="px-3 py-2">
        <span className={`rounded border px-1.5 py-0.5 text-2xs ${ROLE_TONE[fact.role] || ROLE_TONE.context}`}>
          {fact.role}
        </span>
      </td>
      <td className="px-3 py-2">
        {carriers.length > 0 ? (
          <div className="space-y-0.5">
            {uniqueValues.slice(0, 2).map((value) => (
              <div key={value} className="truncate font-mono text-2xs text-ink-muted" title={value}>
                {value}
              </div>
            ))}
            {uniqueValues.length > 2 && (
              <div className="text-2xs text-ink-faint">+{uniqueValues.length - 2} more values</div>
            )}
          </div>
        ) : (
          <span className="text-2xs text-ink-faint">missing</span>
        )}
      </td>
      <td className="tabular px-3 py-2 text-right text-xs text-ink-muted">{fact.weight.toFixed(3)}</td>
      <td className="tabular px-3 py-2 text-right text-xs text-ink-muted">{fact.quality.toFixed(2)}</td>
      <td className="tabular px-3 py-2 text-right text-xs text-ink-muted">{fact.confidence.toFixed(2)}</td>
      <td className="tabular px-3 py-2 text-right text-xs text-ink">{fact.contribution.toFixed(3)}</td>
      <td className="px-3 py-2 text-2xs text-ink-faint">{carriers.length}</td>
    </tr>
  )
}

export default function CaseDetail({ caseId, onBack, onOpenAlert }) {
  const [detail, setDetail] = useState(null)
  const [timeline, setTimeline] = useState({ nodes: [], edges: [] })

  useEffect(() => {
    setDetail(null)
    fetchCaseDetail(caseId).then(setDetail).catch(() => setDetail(null))
    fetchTimeline(caseId).then(setTimeline).catch(() => setTimeline({ nodes: [], edges: [] }))
  }, [caseId])

  const facts = detail?.case?.facts || []
  const topContributions = useMemo(
    () => [...facts].sort((a, b) => b.contribution - a.contribution).slice(0, 8),
    [facts],
  )

  if (!detail) {
    return <p className="py-10 text-center text-sm text-ink-faint">Loading case…</p>
  }
  if (!detail.case) {
    return <p className="py-10 text-center text-sm text-ink-faint">Case not found.</p>
  }

  const { case: data, summary } = detail
  const techniqueLabel = TECH_LABELS[data.technique] || data.technique
  const maxContribution = topContributions[0]?.contribution || 1

  return (
    <div className="space-y-4">
      <button onClick={onBack} className="text-xs text-accent hover:text-blue-400">
        ← Back to cases
      </button>

      <Panel>
        <div className="flex flex-wrap items-start justify-between gap-4 p-4">
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <TechniqueTag technique={data.technique} label={`${data.technique} · ${techniqueLabel}`} />
              <span className="text-2xs text-ink-faint">{data.profile_name}</span>
            </div>
            <h1 className="mt-2 truncate text-base font-semibold text-ink">
              {summary.seed?.rule?.description || 'Correlated case'}
            </h1>
            <dl className="mt-3 grid grid-cols-2 gap-x-8 gap-y-3 md:grid-cols-4">
              <KeyValue label="Case ID" mono>
                {shortId(data.case_id, 28)}
              </KeyValue>
              <KeyValue label="Host">{summary.seed?.agent || '-'}</KeyValue>
              <KeyValue label="Seed time" mono>
                {formatTime(summary.seed?.timestamp)}
              </KeyValue>
              <KeyValue label="Events">
                {data.nodes} nodes · {data.edges} edges
              </KeyValue>
            </dl>
          </div>
          <div className="text-right">
            <div className="tabular text-4xl font-semibold text-ink">{data.case_score}</div>
            <div className="mt-1 flex items-center justify-end gap-2">
              <LevelBadge level={data.level} />
              <span className="text-2xs text-ink-faint">case actionability</span>
            </div>
            <button
              onClick={() => onOpenAlert(data.case_id)}
              className="mt-3 rounded border border-edge px-2 py-1 text-2xs text-ink-muted hover:border-accent hover:text-accent"
            >
              Open seed alert
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 border-t border-edge p-4 md:grid-cols-3">
          <div>
            <div className="flex items-center justify-between text-2xs text-ink-faint">
              <span>Case score</span>
              <span className="tabular">{data.case_score}/100</span>
            </div>
            <Meter value={data.case_score} tone={levelTone(data.level)} className="mt-1.5" />
          </div>
          <div>
            <div className="flex items-center justify-between text-2xs text-ink-faint">
              <span>Required evidence</span>
              <span className="tabular">
                {data.required_covered}/{data.required_total}
              </span>
            </div>
            <Meter value={data.required_coverage * 100} tone="bg-accent" className="mt-1.5" />
          </div>
          <div>
            <div className="flex items-center justify-between text-2xs text-ink-faint">
              <span>Relations in case</span>
              <span className="tabular">{timeline.edges?.length || 0}</span>
            </div>
            <Meter value={timeline.edges?.length || 0} max={Math.max(6, timeline.edges?.length || 1)} tone="bg-ink-faint" className="mt-1.5" />
          </div>
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Panel>
            <SectionTitle right={<span className="text-2xs text-ink-faint">weight · quality · evidence confidence</span>}>
              Evidence facts
            </SectionTitle>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-edge text-2xs uppercase tracking-wider text-ink-faint">
                    <th className="px-3 py-2 font-medium">Field</th>
                    <th className="px-3 py-2 font-medium">Role</th>
                    <th className="px-3 py-2 font-medium">Value / carriers</th>
                    <th className="px-3 py-2 text-right font-medium">W</th>
                    <th className="px-3 py-2 text-right font-medium">Q</th>
                    <th className="px-3 py-2 text-right font-medium">E</th>
                    <th className="px-3 py-2 text-right font-medium">Contrib</th>
                    <th className="px-3 py-2 font-medium">n</th>
                  </tr>
                </thead>
                <tbody>
                  {facts.map((fact) => (
                    <FactRow key={fact.field} fact={fact} />
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel>
            <SectionTitle right={<span className="text-2xs text-ink-faint">{timeline.nodes?.length || 0} events</span>}>
              Case timeline
            </SectionTitle>
            <TimelineView nodes={timeline.nodes} edges={timeline.edges} seedId={caseId} />
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel>
            <SectionTitle>Score composition</SectionTitle>
            <div className="space-y-2 p-4">
              {topContributions.length === 0 && <EmptyState title="No evidence facts" />}
              {topContributions.map((fact) => (
                <div key={fact.field}>
                  <div className="flex items-center justify-between text-2xs">
                    <span className="text-ink-muted">{fact.label}</span>
                    <span className="tabular text-ink">{fact.contribution.toFixed(3)}</span>
                  </div>
                  <Meter value={fact.contribution} max={maxContribution} tone="bg-accent" height="h-1" className="mt-1" />
                </div>
              ))}
            </div>
          </Panel>

          <Panel>
            <SectionTitle>Typed relations</SectionTitle>
            <div className="divide-y divide-edge/70">
              {(!timeline.edges || timeline.edges.length === 0) && (
                <EmptyState title="No correlation edges" hint="Seed alert stands alone." />
              )}
              {timeline.edges?.map((edge, index) => (
                <div key={`${edge.source}-${edge.target}-${index}`} className="px-4 py-2.5">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-2xs text-ink">{edge.relation}</span>
                    <span className="tabular text-2xs text-ink-muted">{edge.confidence?.toFixed(3)}</span>
                  </div>
                  <div className="mt-1 flex items-center justify-between text-2xs text-ink-faint">
                    <span className="font-mono">
                      {shortId(edge.source, 10)} → {shortId(edge.target, 10)}
                    </span>
                    <span>
                      {edge.decision}
                      {edge.delta_s != null ? ` · ${Number(edge.delta_s).toFixed(1)}s` : ''}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  )
}
