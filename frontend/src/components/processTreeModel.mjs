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
//
// The tree is a *process creation* view: it shows only the seed's lineage
// (ancestors and descendants reached through parent-process GUIDs). Processes
// that entered the case through context correlations (e.g. SAME_BINARY) are
// excluded from the tree but are still counted in the case score. When there
// is no seed, the tree falls back to showing every group.
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
  for (const key of groups.keys()) {
    const parent = parents.get(key)
    if (parent) {
      if (!children.has(parent)) children.set(parent, [])
      children.get(parent).push(key)
    }
  }

  // Lineage of the seed only: ancestors (up) union descendants (down).
  const included = new Set()
  if (seedKey) {
    let cursor = seedKey
    while (cursor && !included.has(cursor)) {
      included.add(cursor)
      cursor = parents.get(cursor)
    }
    const stack = [seedKey]
    while (stack.length) {
      const key = stack.pop()
      for (const child of children.get(key) || []) {
        if (!included.has(child)) {
          included.add(child)
          stack.push(child)
        }
      }
    }
  }
  const keep = (key) => !seedKey || included.has(key)

  const visibleGroups = new Map([...groups].filter(([key]) => keep(key)))
  const visibleReps = new Map([...reps].filter(([key]) => keep(key)))
  const visibleChildren = new Map(
    [...children]
      .filter(([key]) => keep(key))
      .map(([key, list]) => [key, list.filter(keep)]),
  )
  const roots = [...visibleGroups.keys()].filter((key) => !parents.get(key))

  const order = (a, b) =>
    (visibleReps.get(a)?.timestamp || '').localeCompare(
      visibleReps.get(b)?.timestamp || '',
    )
  roots.sort(order)
  for (const list of visibleChildren.values()) list.sort(order)

  return {
    groups: visibleGroups,
    reps: visibleReps,
    children: visibleChildren,
    roots,
    seedKey,
    lineageWarnings: new Set([...lineageWarnings].filter(keep)),
    excludedCount: groups.size - visibleGroups.size,
    totalGroups: groups.size,
  }
}
