import { useMemo } from 'react'
import { Badge, EmptyState, formatTime } from './ui'
import { buildProcessTree, EVENT_LABELS } from './processTreeModel.mjs'

const baseName = (path) => path?.split(/[\\/]/).pop()
const sessionLabel = (node) =>
  node.is_system
    ? 'System session'
    : node.is_system === false || node.user
      ? 'User session'
      : 'Session unknown'

function ProcessBranch({ procKey, tree, seedId }) {
  const rep = tree.reps.get(procKey)
  const items = tree.groups.get(procKey)
  const children = tree.children.get(procKey) || []
  const isSeed = tree.seedKey === procKey
  const missingParent =
    rep.parent_process_guid && !tree.groups.has(rep.parent_process_guid)
  const command = rep.command_line || rep.summary
  return (
    <li>
      <div className={`tree-node ${isSeed ? 'tree-node-seed' : ''}`}>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <span className="break-all font-mono text-small font-medium">
            {rep.process || baseName(rep.executable) || 'Unknown process'}
          </span>
          {isSeed && (
            <Badge className="border-accent/50 text-accent">SEED</Badge>
          )}
          <span className="text-caption text-ink-muted">
            {sessionLabel(rep)}
          </span>
          <time
            className="ml-auto text-caption text-ink-faint"
            dateTime={rep.timestamp}
          >
            {formatTime(rep.timestamp)}
          </time>
        </div>
        {rep.user && (
          <p className="mt-1 break-all text-caption text-ink-faint">
            {rep.user}
          </p>
        )}
        {command && (
          <p
            className="mt-2 truncate font-mono text-caption text-ink-muted"
            title={command}
          >
            {command}
          </p>
        )}
        {missingParent && (
          <p className="mt-2 text-caption text-ink-muted">
            ↑ Uncaptured parent
            {rep.parent_process ? `: ${rep.parent_process}` : ''}{' '}
            <span className="text-ink-faint">
              · outside the captured evidence
            </span>
          </p>
        )}
        {tree.lineageWarnings.has(procKey) && (
          <p className="mt-2 text-caption text-ink-muted">
            Conflicting parent reference; displayed as a root.
          </p>
        )}
        <details className="mt-2 text-caption">
          <summary className="w-fit cursor-pointer text-ink-muted hover:text-ink">
            {items.length} {items.length === 1 ? 'event' : 'events'} · Process
            details
          </summary>
          <div className="mt-3 space-y-3 border-l border-edge-strong pl-3">
            {rep.process_guid && (
              <p className="mono-value">
                <span className="font-sans text-ink-faint">Process GUID </span>
                {rep.process_guid}
              </p>
            )}
            {rep.executable && <p className="mono-value">{rep.executable}</p>}
            {command && (
              <p className="mono-value whitespace-pre-wrap">{command}</p>
            )}
            <ol className="divide-y divide-edge">
              {items.map((node) => (
                <li key={node.id} className="py-2">
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <time className="text-ink-faint" dateTime={node.timestamp}>
                      {formatTime(node.timestamp)}
                    </time>
                    <span>
                      EID {node.event_id ?? '—'} ·{' '}
                      {EVENT_LABELS[node.event_id] || 'Event'}
                    </span>
                    {node.id === seedId && (
                      <span className="font-medium text-accent">SEED</span>
                    )}
                  </div>
                  {node.summary && (
                    <p className="mono-value mt-1">{node.summary}</p>
                  )}
                  <p className="mono-value mt-1 text-ink-faint">{node.id}</p>
                </li>
              ))}
            </ol>
          </div>
        </details>
      </div>
      {children.length > 0 && (
        <ul className="tree-branches">
          {children.map((key) => (
            <ProcessBranch
              key={key}
              procKey={key}
              tree={tree}
              seedId={seedId}
            />
          ))}
        </ul>
      )}
    </li>
  )
}

export default function ProcessTree({ nodes = [], seedId }) {
  const tree = useMemo(() => buildProcessTree(nodes, seedId), [nodes, seedId])
  if (!nodes.length)
    return (
      <EmptyState
        title="No process events"
        hint="There are no captured process events for this case."
      />
    )
  const reps = [...tree.reps.values()]
  const systemCount = reps.filter((node) => node.is_system).length
  const userCount = reps.filter(
    (node) => !node.is_system && (node.is_system === false || node.user),
  ).length
  return (
    <div className="p-5">
      <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-caption text-ink-muted">
        <strong className="font-medium text-ink">
          {tree.groups.size} process groups
        </strong>
        <span>
          {systemCount} System · {userCount} User
        </span>
        <span className="text-ink-faint">
          Parent → child · Roots are the highest captured ancestors
        </span>
      </div>
      <div
        className="max-h-[680px] overflow-auto pr-2"
        tabIndex={0}
        role="region"
        aria-label="Process hierarchy"
      >
        <ul className="min-w-[560px] space-y-2">
          {tree.roots.map((key) => (
            <ProcessBranch
              key={key}
              procKey={key}
              tree={tree}
              seedId={seedId}
            />
          ))}
        </ul>
      </div>
    </div>
  )
}
