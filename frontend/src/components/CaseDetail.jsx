import { useEffect, useState } from 'react'
import { fetchCaseDetail, fetchTimeline } from '../api'
import TimelineView from './TimelineView'
import ProcessTree from './ProcessTree'
import EvidenceFacts from './EvidenceFacts'
import { buildReport, downloadReport, safeFilename } from './caseReport'
import {
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
  shortId,
} from './ui'

export default function CaseDetail({ caseId, onBack, onOpenAlert }) {
  const [detail, setDetail] = useState(null)
  const [timeline, setTimeline] = useState(null)
  const [error, setError] = useState(null)
  const [timelineError, setTimelineError] = useState(null)
  const [hideMissing, setHideMissing] = useState(false)
  useEffect(() => {
    let active = true
    setDetail(null)
    setTimeline(null)
    setError(null)
    setTimelineError(null)
    setHideMissing(false)
    fetchCaseDetail(caseId)
      .then((data) => {
        if (active) setDetail(data)
      })
      .catch(() => {
        if (active) setError('The requested case could not be loaded.')
      })
    fetchTimeline(caseId)
      .then((data) => {
        if (active) setTimeline(data)
      })
      .catch(() => {
        if (active)
          setTimelineError('Process and event data could not be loaded.')
      })
    return () => {
      active = false
    }
  }, [caseId])
  const back = (
    <button onClick={onBack} className="text-link">
      ← Back to cases
    </button>
  )
  if (error)
    return (
      <div>
        {back}
        <Panel className="mt-5">
          <EmptyState title="Case unavailable" hint={error} />
        </Panel>
      </div>
    )
  if (!detail)
    return (
      <div>
        {back}
        <Panel className="mt-5">
          <SkeletonRows rows={8} />
        </Panel>
      </div>
    )
  if (!detail.case)
    return (
      <div>
        {back}
        <EmptyState title="Case not found" />
      </div>
    )
  const { case: data, summary } = detail
  const facts = data.facts || []
  const visibleFacts = hideMissing
    ? facts.filter((fact) => fact.completeness === 1)
    : facts
  const topContributions = [...facts]
    .sort((a, b) => b.contribution - a.contribution)
    .slice(0, 8)
  const exportReport = () =>
    downloadReport(
      `case-${safeFilename(data.case_id)}.md`,
      buildReport(detail, timeline || { nodes: [], edges: [] }),
    )
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        {back}
        <button onClick={() => onOpenAlert(data.case_id)} className="control">
          Open seed alert ↗
        </button>
      </div>
      <Panel className="overflow-hidden">
        <div className="flex flex-col lg:flex-row">
          <div className="min-w-0 flex-1 p-6">
            <p className="eyebrow">Case investigation</p>
            <div className="mt-3">
              <TechniqueTag
                technique={data.technique}
                label={`${data.technique} · ${TECH_LABELS[data.technique] || data.profile_name}`}
              />
            </div>
            <h1
              className="mt-3 line-clamp-2 break-words text-title font-semibold"
              title={summary.seed?.rule?.description}
            >
              {summary.seed?.rule?.description?.trim() || 'Correlated case'}
            </h1>
            <details className="mt-2 text-caption">
              <summary className="cursor-pointer text-ink-muted">
                Full rule description and case ID
              </summary>
              <p className="mono-value mt-3">
                {summary.seed?.rule?.description}
              </p>
              <p className="mono-value mt-2">{data.case_id}</p>
            </details>
            <dl className="mt-6 grid grid-cols-2 gap-x-6 gap-y-5 sm:grid-cols-3">
              <KeyValue label="Endpoint">{summary.seed?.agent || '—'}</KeyValue>
              <KeyValue label="Wazuh rule level">
                <WazuhBadge level={summary.seed?.rule?.level} />
              </KeyValue>
              <KeyValue label="Seed time · UTC">
                {formatTime(summary.seed?.timestamp)}
              </KeyValue>
              <KeyValue label="Case ID" mono>
                <span title={data.case_id}>{shortId(data.case_id, 26)}</span>
              </KeyValue>
              <KeyValue label="Required evidence">
                {data.required_covered} / {data.required_total} fields
              </KeyValue>
              <KeyValue label="Telemetry">
                {data.nodes} events · {data.edges} relations
              </KeyValue>
            </dl>
          </div>
          <ScoreCard
            label="Case actionability"
            score={data.case_score}
            level={data.level}
            covered={facts.filter((f) => f.completeness === 1).length}
            total={facts.length}
          />
        </div>
      </Panel>
      {data.aggregation_provenance_truncated && (
        <p className="notice">
          Evidence aggregation reached its sample limit. Additional carrier
          provenance is summarized, rather than individually listed.
        </p>
      )}
      <Panel>
        <SectionTitle
          description="W: AHP weight · Q: quality · E: evidence confidence"
          right={
            <div className="flex flex-wrap gap-2">
              <button
                aria-pressed={hideMissing}
                className={`control ${hideMissing ? 'control-active' : ''}`}
                onClick={() => setHideMissing((v) => !v)}
              >
                {hideMissing ? 'Showing present only' : 'Hide missing'}
              </button>
              <button
                className="control"
                onClick={exportReport}
                disabled={!timeline}
              >
                Export report ↓
              </button>
            </div>
          }
        >
          Evidence facts{' '}
          <span className="ml-2 text-small font-normal text-ink-faint">
            {visibleFacts.length}
          </span>
        </SectionTitle>
        <EvidenceFacts facts={visibleFacts} />
      </Panel>
      <Panel>
        <SectionTitle
          description="Process creation is the hierarchy; other events stay with their process."
          right={
            <span className="text-caption text-ink-muted">
              {timeline?.nodes?.length ?? '—'} captured events
            </span>
          }
        >
          Process creation tree
        </SectionTitle>
        {timelineError ? (
          <EmptyState title="Process data unavailable" hint={timelineError} />
        ) : !timeline ? (
          <SkeletonRows />
        ) : (
          <ProcessTree nodes={timeline.nodes} seedId={caseId} />
        )}
      </Panel>
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <Panel>
          <SectionTitle description="Largest weighted contributions">
            Score composition
          </SectionTitle>
          <div className="space-y-5 p-5">
            {!topContributions.length && (
              <EmptyState title="No evidence facts" />
            )}
            {topContributions.map((fact) => (
              <div key={fact.field}>
                <div className="mb-2 flex justify-between gap-3 text-small">
                  <span className="text-ink-muted">{fact.label}</span>
                  <span className="font-mono text-caption">
                    {fact.contribution.toFixed(3)}
                  </span>
                </div>
                <Meter
                  value={fact.contribution}
                  max={topContributions[0]?.contribution || 1}
                />
              </div>
            ))}
          </div>
        </Panel>
        <Panel>
          <SectionTitle
            description="Relations supported by the correlation engine"
            right={
              <span className="text-caption text-ink-faint">
                Confidence · Δ time
              </span>
            }
          >
            Typed relations
          </SectionTitle>
          {timelineError ? (
            <EmptyState
              title="Relation data unavailable"
              hint={timelineError}
            />
          ) : !timeline ? (
            <SkeletonRows />
          ) : !timeline.edges?.length ? (
            <EmptyState
              title="No correlation edges"
              hint="No related event matched within the correlation windows."
            />
          ) : (
            <div className="max-h-[440px] divide-y divide-edge overflow-auto">
              {timeline.edges.map((edge, i) => (
                <div
                  key={`${edge.source}-${edge.target}-${i}`}
                  className="px-5 py-3"
                >
                  <div className="flex flex-wrap justify-between gap-2">
                    <span className="font-mono text-caption">
                      {edge.relation}
                    </span>
                    <span className="font-mono text-caption text-ink-muted">
                      {edge.confidence?.toFixed(3)}
                      {edge.delta_s != null
                        ? ` · ${Number(edge.delta_s).toFixed(1)}s`
                        : ''}
                    </span>
                  </div>
                  <div className="mt-1 flex flex-wrap justify-between gap-2 text-caption text-ink-faint">
                    <span
                      className="font-mono"
                      title={`${edge.source} → ${edge.target}`}
                    >
                      {shortId(edge.source, 28)} → {shortId(edge.target, 28)}
                    </span>
                    <span>{edge.decision}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
      <Panel>
        <SectionTitle
          description="Captured events in chronological order"
          right={<span className="text-caption text-ink-faint">UTC</span>}
        >
          Event order
        </SectionTitle>
        {timelineError ? (
          <EmptyState title="Event data unavailable" hint={timelineError} />
        ) : !timeline ? (
          <SkeletonRows />
        ) : (
          <TimelineView
            nodes={timeline.nodes}
            edges={timeline.edges}
            seedId={caseId}
          />
        )}
      </Panel>
    </div>
  )
}
