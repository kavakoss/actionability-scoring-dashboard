export const EVENT_LABELS = {
  1: 'Process create',
  3: 'Network connect',
  5: 'Process terminate',
  11: 'File create',
  12: 'Registry create',
  13: 'Registry set',
  22: 'DNS query',
  4624: 'Logon',
}

// Group the existing events for display; this does not add correlation edges.
export function buildProcessTree(nodes, seedId) {
  const groups = new Map()
  for (const node of nodes) {
    const key = node.process_guid || node.id
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(node)
  }
  const reps = new Map()
  let seedKey = null
  for (const [key, items] of groups) {
    items.sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''))
    reps.set(
      key,
      items.find((node) => String(node.event_id) === '1') || items[0],
    )
    if (items.some((node) => node.id === seedId)) seedKey = key
  }
  const parents = new Map()
  const lineageWarnings = new Set()
  for (const [key, rep] of reps) {
    const parent = rep.parent_process_guid
    if (!parent || !groups.has(parent)) continue
    const visited = new Set([key])
    let cursor = parent
    while (cursor && !visited.has(cursor)) {
      visited.add(cursor)
      cursor = parents.get(cursor)
    }
    if (cursor) lineageWarnings.add(key)
    else parents.set(key, parent)
  }
  const children = new Map()
  const roots = []
  for (const key of groups.keys()) {
    const parent = parents.get(key)
    if (!parent) roots.push(key)
    else {
      if (!children.has(parent)) children.set(parent, [])
      children.get(parent).push(key)
    }
  }
  const order = (a, b) =>
    (reps.get(a).timestamp || '').localeCompare(reps.get(b).timestamp || '')
  roots.sort(order)
  for (const list of children.values()) list.sort(order)
  return { groups, reps, children, roots, seedKey, lineageWarnings }
}
