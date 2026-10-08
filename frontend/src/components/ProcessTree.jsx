import { useMemo } from 'react'
import { shortId } from './ui'

const EVENT_LABEL = {
  1: 'Process Create',
  3: 'Network Connect',
  5: 'Process Terminate',
  11: 'File Create',
  22: 'DNS Query',
  12: 'Registry Create',
  13: 'Registry Set',
}

function formatTime(value) {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(
    date.getSeconds(),
  ).padStart(2, '0')}`
}

function baseName(path) {
  if (!path) return null
  return path.replace('/', '\\').split('\\').pop()
}

function buildTree(nodes, seedId) {
  const groups = new Map()
  for (const node of nodes) {
    const key = node.process_guid || node.id
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(node)
  }

  const reps = new Map()
  for (const [key, items] of groups) {
    const create = items.find((node) => String(node.event_id) === '1')
    reps.set(key, create || items[0])
  }

  const keys = new Set(groups.keys())
  const children = new Map()
  const roots = []
  for (const [key, rep] of reps) {
    const parentKey = rep.parent_process_guid
    if (parentKey && keys.has(parentKey) && parentKey !== key) {
      if (!children.has(parentKey)) children.set(parentKey, [])
      children.get(parentKey).push(key)
    } else {
      roots.push(key)
    }
  }

  const order = (key) => reps.get(key)?.timestamp || ''
  for (const list of children.values()) list.sort((a, b) => order(a).localeCompare(order(b)))
  roots.sort((a, b) => order(a).localeCompare(order(b)))

  let seedKey = null
  for (const [key, items] of groups) {
    if (items.some((node) => node.id === seedId)) seedKey = key
  }

  return { groups, reps, children, roots, seedKey }
}

function TreeRow({ procKey, tree, seedId, depth, isLast, ancestorsLast }) {
  const { groups, reps, children, seedKey } = tree
  const items = groups.get(procKey) || []
  const rep = reps.get(procKey)
  const isSeed = procKey === seedKey
  const kids = children.get(procKey) || []
  const session = rep?.is_system ? 'System' : 'User'
  const createNode = items.find((node) => String(node.event_id) === '1')
  const commandLine = rep?.command_line || createNode?.summary || rep?.summary
  const eventIds = [...new Set(items.map((node) => String(node.event_id)))].sort()
  const missingParent =
    depth === 0 && rep?.parent_process_guid && !tree.groups.has(rep.parent_process_guid)
      ? rep.parent_process || 'unknown'
      : null

  return (
    <li className="relative">
      {depth > 0 && (
        <span
          className="absolute left-0 top-0 h-6 w-4 rounded-bl border-b border-l border-edge"
          style={{ left: `${(depth - 1) * 20}px` }}
          aria-hidden="true"
        />
      )}
      <div className="relative" style={{ paddingLeft: `${depth * 20}px` }}>
        <div
          className={`flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border px-3 py-2 ${
            isSeed ? 'border-accent/50 bg-accent/5' : 'border-edge bg-raised/40'
          }`}
        >
          <span className={`font-medium ${isSeed ? 'text-accent' : 'text-ink'}`}>
            {rep?.process || baseName(rep?.executable) || 'process'}
          </span>
          {isSeed && (
            <span className="rounded border border-accent/50 px-1.5 py-0.5 text-xs font-medium text-accent">
              SEED
            </span>
          )}
          <span
            className={`rounded-full px-2 py-0.5 text-xs font-medium ${
              rep?.is_system ? 'bg-raised text-ink-muted' : 'bg-band-high/10 text-band-high'
            }`}
          >
            {session}
          </span>
          <span className="tabular font-mono text-xs text-ink-faint">{formatTime(rep?.timestamp)}</span>
          {eventIds.map((eventId) => (
            <span
              key={eventId}
              className="rounded border border-edge px-1.5 py-0.5 font-mono text-xs text-ink-muted"
            >
              EID {eventId} · {EVENT_LABEL[eventId] || 'Event'}
            </span>
          ))}
          {missingParent && (
            <span
              className="rounded border border-sev-medium/40 bg-sev-medium/5 px-1.5 py-0.5 text-xs text-sev-medium"
              title="The parent process was not captured in this case (depth/telemetry limit)."
            >
              ↑ parent: {missingParent} (not captured)
            </span>
          )}
        </div>
        <div className="mt-1 space-y-0.5 pl-3">
          {rep?.user && <p className="text-xs text-ink-faint">{rep.user}</p>}
          {commandLine && (
            <p className="truncate font-mono text-xs text-ink-muted" title={commandLine}>
              {commandLine}
            </p>
          )}
          {items.length > 1 && (
            <p className="text-xs text-ink-faint">
              {items.length} events · {items.map((node) => node.id).slice(0, 3).map((id) => shortId(id, 8)).join(', ')}
              {items.length > 3 ? ' …' : ''}
            </p>
          )}
        </div>
      </div>

      {kids.length > 0 && (
        <ul className="relative mt-1 space-y-1">
          {kids.map((kid) => (
            <TreeRow
              key={kid}
              procKey={kid}
              tree={tree}
              seedId={seedId}
              depth={depth + 1}
              isLast={false}
              ancestorsLast={ancestorsLast}
            />
          ))}
        </ul>
      )}
    </li>
  )
}

export default function ProcessTree({ nodes = [], seedId }) {
  const tree = useMemo(() => buildTree(nodes, seedId), [nodes, seedId])

  if (nodes.length === 0) {
    return <p className="px-5 py-6 text-sm text-ink-faint">No process events for this case.</p>
  }

  const systemCount = [...tree.groups.keys()].filter((key) => tree.reps.get(key)?.is_system).length
  const userCount = tree.groups.size - systemCount

  return (
    <div className="p-5">
      <div className="mb-3 flex flex-wrap items-center gap-3 text-xs text-ink-muted">
        <span className="font-medium text-ink">{tree.groups.size} processes</span>
        <span className="rounded-full bg-raised px-2 py-0.5">{systemCount} system</span>
        <span className="rounded-full bg-band-high/10 px-2 py-0.5 text-band-high">{userCount} user</span>
        <span className="text-ink-faint">Indented by parent → child; root = highest ancestor captured</span>
      </div>

      {tree.roots.length === 0 && (
        <p className="text-sm text-ink-faint">No process lineage could be reconstructed.</p>
      )}

      <ul className="space-y-1">
        {tree.roots.map((rootKey) => (
          <TreeRow key={rootKey} procKey={rootKey} tree={tree} seedId={seedId} depth={0} isLast={false} />
        ))}
      </ul>
    </div>
  )
}
