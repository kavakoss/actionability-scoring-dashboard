const BASE = '/api'

export async function fetchAlerts(params = {}) {
  const qs = new URLSearchParams(params).toString()
  const res = await fetch(`${BASE}/alerts?${qs}`)
  return res.json()
}

export async function fetchAlertDetail(id) {
  const res = await fetch(`${BASE}/alerts/${id}`)
  if (!res.ok) throw new Error('Not found')
  return res.json()
}

export async function fetchTimeline(id) {
  const res = await fetch(`${BASE}/timeline/${id}`)
  if (!res.ok) throw new Error('Not found')
  return res.json()
}

export async function fetchStats() {
  const res = await fetch(`${BASE}/stats`)
  return res.json()
}

export async function fetchCases(params = {}) {
  const qs = new URLSearchParams(params).toString()
  const res = await fetch(`${BASE}/cases?${qs}`)
  return res.json()
}

export async function fetchCaseDetail(id) {
  const res = await fetch(`${BASE}/cases/${encodeURIComponent(id)}`)
  if (!res.ok) throw new Error('Not found')
  return res.json()
}

export async function fetchHealth() {
  const res = await fetch(`${BASE}/health`)
  return res.json()
}

export async function setSource(source) {
  const res = await fetch(`${BASE}/source`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source }),
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.detail || 'Failed to switch source')
  return data
}
