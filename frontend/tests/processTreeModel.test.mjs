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

test('retains uncaptured-parent groups and events without process GUIDs', () => {
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
  assert.deepEqual(tree.roots, ['child', 'no-guid'])
  assert.equal(tree.reps.get('child').parent_process_guid, 'uncaptured')
  assert.equal(tree.groups.size, 2)
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
