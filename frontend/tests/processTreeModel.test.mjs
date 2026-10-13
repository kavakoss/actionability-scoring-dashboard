import test from 'node:test'
import assert from 'node:assert/strict'
import { buildProcessTree } from '../src/components/processTreeModel.mjs'

test('groups events under their process creation and marks a non-creation seed', () => {
  const tree = buildProcessTree(
    [
      {
        id: 'net',
        process_guid: 'child',
        event_id: 3,
        timestamp: '2026-10-03T01:00:03Z',
      },
      {
        id: 'child-create',
        process_guid: 'child',
        parent_process_guid: 'parent',
        event_id: '1',
        timestamp: '2026-10-03T01:00:02Z',
      },
      {
        id: 'parent-create',
        process_guid: 'parent',
        event_id: 1,
        timestamp: '2026-10-03T01:00:01Z',
      },
    ],
    'net',
  )
  assert.deepEqual(tree.roots, ['parent'])
  assert.deepEqual(tree.children.get('parent'), ['child'])
  assert.equal(tree.reps.get('child').id, 'child-create')
  assert.deepEqual(
    tree.groups.get('child').map((n) => n.id),
    ['child-create', 'net'],
  )
  assert.equal(tree.seedKey, 'child')
})

test('keeps the seed lineage and excludes context-only processes', () => {
  const tree = buildProcessTree(
    [
      {
        id: 'orphan',
        process_guid: 'child',
        parent_process_guid: 'uncaptured',
      },
      { id: 'no-guid' },
    ],
    'orphan',
  )
  assert.deepEqual(tree.roots, ['child'])
  assert.equal(tree.reps.get('child').parent_process_guid, 'uncaptured')
  assert.equal(tree.groups.size, 1)
  assert.equal(tree.excludedCount, 1)
  assert.equal(tree.totalGroups, 2)
})

test('hides a process that is not on the seed lineage', () => {
  const tree = buildProcessTree(
    [
      { id: 'p', process_guid: 'parent', event_id: '1', timestamp: '2026-10-03T01:00:00Z' },
      { id: 's', process_guid: 'seed', parent_process_guid: 'parent', event_id: '1', timestamp: '2026-10-03T01:00:01Z' },
      { id: 'c', process_guid: 'child', parent_process_guid: 'seed', event_id: '1', timestamp: '2026-10-03T01:00:02Z' },
      // attached to the case by a SAME_BINARY-style context relation, not lineage
      { id: 'x', process_guid: 'other', event_id: '1', timestamp: '2026-10-03T01:00:03Z' },
    ],
    's',
  )
  assert.deepEqual(tree.roots, ['parent'])
  assert.deepEqual(tree.children.get('seed'), ['child'])
  assert.equal(tree.groups.size, 3)
  assert.equal(tree.excludedCount, 1)
})

test('malformed cyclic parent references cannot hide events or recurse forever', () => {
  const tree = buildProcessTree([
    { id: 'a', process_guid: 'a', parent_process_guid: 'b' },
    { id: 'b', process_guid: 'b', parent_process_guid: 'a' },
    { id: 'c', process_guid: 'c', parent_process_guid: 'c' },
  ])
  const visited = []
  const walk = (key) => {
    assert.ok(!visited.includes(key))
    visited.push(key)
    ;(tree.children.get(key) || []).forEach(walk)
  }
  tree.roots.forEach(walk)
  assert.deepEqual(visited.sort(), ['a', 'b', 'c'])
  assert.equal(tree.lineageWarnings.size, 2)
})

test('orders roots chronologically without mutating the input', () => {
  const nodes = [
    { id: 'later', timestamp: '2026-10-03' },
    { id: 'earlier', timestamp: '2026-10-02' },
  ]
  assert.deepEqual(buildProcessTree(nodes).roots, ['earlier', 'later'])
  assert.deepEqual(
    nodes.map((n) => n.id),
    ['later', 'earlier'],
  )
})
