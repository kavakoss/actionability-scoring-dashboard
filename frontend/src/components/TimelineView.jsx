const EVENT_LABEL = {
  '1': 'Process Create',
  '3': 'Network Connect',
  '5': 'Process Terminate',
  '11': 'File Create',
  '22': 'DNS Query',
  '4624': 'Logon',
}

function formatTime(value) {
  if (!value) return '-'
  const date = new Date(value)
  return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(
    date.getSeconds(),
  ).padStart(2, '0')}`
}

export default function TimelineView({ nodes = [], edges = [], seedId }) {
  const sorted = [...nodes].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''))

  if (sorted.length === 0) {
    return <p className="px-4 py-6 text-xs text-ink-faint">No correlated events for this case.</p>
  }

  return (
    <ol className="relative px-4 py-3">
      <span className="absolute bottom-4 left-[27px] top-4 w-px bg-edge" aria-hidden="true" />
      {sorted.map((node) => {
        const isSeed = node.id === seedId
        return (
          <li key={node.id} className="relative flex gap-3 py-2 pl-0">
            <span
              className={`relative z-10 mt-1 h-2.5 w-2.5 shrink-0 rounded-sm border ${
                isSeed ? 'border-accent bg-accent' : 'border-edge bg-raised'
              }`}
            />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="tabular font-mono text-2xs text-ink-faint">{formatTime(node.timestamp)}</span>
                <span className="font-mono text-2xs text-ink-muted">
                  EID {node.event_id} · {EVENT_LABEL[node.event_id] || 'Event'}
                </span>
                {isSeed && (
                  <span className="rounded border border-accent/40 px-1 text-2xs font-medium text-accent">SEED</span>
                )}
              </div>
              <div className="mt-0.5 truncate text-xs text-ink">
                {node.process ? <span className="font-medium">{node.process}</span> : node.summary}
              </div>
              {node.summary && node.process && (
                <div className="mt-0.5 truncate font-mono text-2xs text-ink-faint" title={node.summary}>
                  {node.summary}
                </div>
              )}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
