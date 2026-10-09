import { Badge, EmptyState, formatTime, shortId } from './ui'
import { EVENT_LABELS } from './processTreeModel.mjs'

export default function TimelineView({ nodes = [], edges = [], seedId }) {
  const sorted = [...nodes].sort((a, b) =>
    (a.timestamp || '').localeCompare(b.timestamp || ''),
  )
  const positions = new Map(sorted.map((node, i) => [node.id, i]))
  const names = new Map(
    sorted.map((node) => [node.id, node.process || shortId(node.id, 16)]),
  )
  const linksByNode = new Map()
  for (const edge of edges) {
    const source = positions.get(edge.source)
    const target = positions.get(edge.target)
    if (source == null || target == null || source === target) continue
    const later = edge.child_id || (source > target ? edge.source : edge.target)
    const earlier =
      edge.parent_id || (source > target ? edge.target : edge.source)
    if (!linksByNode.has(later)) linksByNode.set(later, [])
    linksByNode
      .get(later)
      .push({
        relation: edge.relation,
        other: earlier,
        confidence: edge.confidence,
      })
  }
  if (!sorted.length) return <EmptyState title="No correlated events" />
  return (
    <div
      className="max-h-[560px] overflow-auto p-5"
      tabIndex={0}
      role="region"
      aria-label="Chronological events"
    >
      <ol>
        {sorted.map((node) => {
          const seed = node.id === seedId
          const links = linksByNode.get(node.id) || []
          return (
            <li
              key={node.id}
              className="relative ml-1 border-l border-edge-strong pb-6 pl-6 last:border-transparent last:pb-0"
            >
              <span
                aria-hidden="true"
                className={`absolute -left-[4.5px] top-1.5 h-2 w-2 rounded-full ${seed ? 'bg-accent' : 'bg-ink-faint'}`}
              />
              <div className="flex flex-col gap-2 sm:flex-row sm:gap-6">
                <time
                  className="w-[120px] shrink-0 text-caption text-ink-faint"
                  dateTime={node.timestamp}
                >
                  {formatTime(node.timestamp)}
                </time>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-3">
                    <span className="text-small font-medium">
                      {node.process || 'Captured event'}
                    </span>
                    <span className="text-caption text-ink-muted">
                      EID {node.event_id ?? '—'} ·{' '}
                      {EVENT_LABELS[node.event_id] || 'Event'}
                    </span>
                    {seed && (
                      <Badge className="border-accent/50 text-accent">
                        SEED
                      </Badge>
                    )}
                  </div>
                  {node.summary && (
                    <p className="mono-value mt-2">{node.summary}</p>
                  )}
                  {links.length > 0 && (
                    <details className="mt-2 text-caption text-ink-muted">
                      <summary className="w-fit cursor-pointer hover:text-ink">
                        {links.length} linked{' '}
                        {links.length === 1 ? 'relation' : 'relations'}
                      </summary>
                      <ul className="mt-2 space-y-2">
                        {links.map((link, i) => (
                          <li
                            key={`${link.relation}-${link.other}-${i}`}
                            className="flex flex-wrap gap-x-3 gap-y-1"
                          >
                            <span className="font-mono">{link.relation}</span>
                            <span title={link.other}>
                              from{' '}
                              {names.get(link.other) || shortId(link.other)}
                            </span>
                            <span className="text-ink-faint">
                              Confidence {link.confidence?.toFixed(3) ?? '—'}
                            </span>
                          </li>
                        ))}
                      </ul>
                    </details>
                  )}
                </div>
              </div>
            </li>
          )
        })}
      </ol>
    </div>
  )
}
