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
