import { useCallback, useEffect, useState } from 'react'
import CasesView from './components/CasesView'
import CaseDetail from './components/CaseDetail'
import ScoringDashboard from './components/ScoringDashboard'
import AlertDetail from './components/AlertDetail'
import StatsOverview from './components/StatsOverview'
import { fetchAlerts, fetchHealth, fetchStats, setSource } from './api'
import { Spinner } from './components/ui'

const TABS = [
  ['cases', 'Cases'],
  ['alerts', 'Alerts'],
]

function readUrl() {
  const params = new URLSearchParams(window.location.search)
  return {
    view: params.get('view') === 'alerts' ? 'alerts' : 'cases',
    caseId: params.get('case'),
    alertId: params.get('alert'),
  }
}

export default function App() {
  const initial = readUrl()
  const [view, setView] = useState(initial.view)
  const [selectedCaseId, setSelectedCaseId] = useState(initial.caseId)
  const [selectedAlertId, setSelectedAlertId] = useState(initial.alertId)
  const [alerts, setAlerts] = useState(null)
  const [stats, setStats] = useState(null)
  const [health, setHealth] = useState(null)
  const [filters, setFilters] = useState({})
  const [switching, setSwitching] = useState(false)
  const [sourceError, setSourceError] = useState(null)
  const [refreshKey, setRefreshKey] = useState(0)
  const dataQuality = health?.data_quality || {}
  const liveWindow =
    health?.config?.live_from && health?.config?.live_to
      ? `${health.config.live_from} → ${health.config.live_to}`
      : `Last ${health?.config?.live_hours_back ?? 48} hours`

  useEffect(() => {
    const params = new URLSearchParams()
    params.set('view', view)
    if (selectedCaseId) params.set('case', selectedCaseId)
    if (selectedAlertId) params.set('alert', selectedAlertId)
    window.history.replaceState(null, '', `?${params.toString()}`)
  }, [view, selectedCaseId, selectedAlertId])

  useEffect(() => {
    fetchHealth().then(setHealth).catch(() => setHealth(null))
  }, [refreshKey])

  useEffect(() => {
    fetchAlerts(filters)
      .then((data) => setAlerts(data.alerts || []))
      .catch(() => setAlerts([]))
    fetchStats().then(setStats).catch(() => setStats(null))
  }, [filters, refreshKey])

  const handleFilter = (key, value) => {
    setFilters((prev) => {
      const next = { ...prev }
      if (value) next[key] = value
      else delete next[key]
      return next
    })
  }

  const switchSource = useCallback(
    async (source) => {
      if (!health || health.source === source || switching) return
      setSwitching(true)
      setSourceError(null)
      try {
        const next = await setSource(source)
        setHealth(next)
        setSelectedCaseId(null)
        setSelectedAlertId(null)
        setAlerts(null)
        setRefreshKey((key) => key + 1)
      } catch (error) {
        setSourceError(String(error.message || error))
      } finally {
        setSwitching(false)
      }
    },
    [health, switching],
  )

  const openCase = (id) => {
    setView('cases')
    setSelectedCaseId(id)
    setSelectedAlertId(null)
  }

  const openAlert = (id) => {
    setView('alerts')
    setSelectedAlertId(id)
    setSelectedCaseId(null)
  }

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-50 border-b border-edge bg-panel/95 backdrop-blur">
        <div className="mx-auto flex min-h-16 max-w-[1440px] items-center justify-between gap-5 px-5">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-accent/15 bg-accent/5">
              <svg viewBox="0 0 24 24" className="h-5 w-5 text-accent" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M3 12h4l2-5 4 10 2-5h6" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </span>
            <div className="hidden sm:block">
              <h1 className="text-sm font-semibold tracking-tight text-ink">Actionability Scoring</h1>
              <p className="text-xs text-ink-muted">Wazuh and Sysmon evidence completeness</p>
            </div>
            <nav className="ml-2 flex h-16 items-center gap-1 sm:ml-5">
              {TABS.map(([value, label]) => (
                <button
                  key={value}
                  onClick={() => {
                    setView(value)
                    setSelectedCaseId(null)
                    setSelectedAlertId(null)
                  }}
                  className={`h-10 rounded-lg px-3 text-sm font-medium transition-colors ${
                    view === value
                      ? 'bg-accent/8 text-accent'
                      : 'text-ink-muted hover:bg-raised hover:text-ink'
                  }`}
                >
                  {label}
                </button>
              ))}
            </nav>
          </div>
          <div className="flex min-w-0 items-center gap-3">
            {health && (
              <div
                className="hidden min-w-0 max-w-[470px] text-right xl:block"
                title={health.source === 'live'
                  ? `Window: ${liveWindow}. Wazuh rule.level >= ${health.config?.seed_min_level}. Raw candidates returned: ${dataQuality.raw_candidates_count ?? 0}. Known-benign exclusions: ${Object.entries(dataQuality.excluded_by_reason || {}).map(([reason, count]) => `${reason}: ${count}`).join('; ') || 'none'}. Omitted by display limit: ${dataQuality.omitted_due_to_display_limit ?? 0}. Raw Wazuh documents are unchanged.`
                  : 'Deterministic mock fixtures; not live Wazuh data.'}
              >
                <div className="flex items-center justify-end gap-2">
                  <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${health.source === 'live' ? 'bg-sev-low/5 text-sev-low' : 'bg-raised text-ink-muted'}`}>
                    {health.source === 'live' ? 'LIVE' : 'MOCK'}
                  </span>
                  <span className="truncate text-xs font-medium text-ink">
                    {health.source === 'live'
                      ? `${liveWindow} · Wazuh level ≥ ${health.config?.seed_min_level}`
                      : 'Deterministic example data'}
                  </span>
                </div>
                <p className="mt-0.5 truncate text-xs text-ink-muted">
                  {health.source === 'live'
                    ? `${health.alerts_count} shown of ${dataQuality.raw_candidates_count ?? 0} candidates · ${dataQuality.excluded_known_benign_count ?? 0} known-benign excluded${dataQuality.query_capped ? ' · fetch cap reached' : ''}`
                    : `${health.alerts_count} sample alerts · ${health.cases_count} sample cases`}
                </p>
              </div>
            )}
            <div className="flex shrink-0 items-center rounded-lg border border-edge bg-raised p-1">
              {['mock', 'live'].map((source) => (
                <button
                  key={source}
                  disabled={switching || !health}
                  onClick={() => switchSource(source)}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium capitalize transition-colors disabled:opacity-40 ${
                    health?.source === source ? 'bg-accent/15 text-accent' : 'text-ink-muted hover:text-ink'
                  }`}
                >
                  {source}
                </button>
              ))}
              {switching && <Spinner className="mx-1.5" />}
            </div>
          </div>
        </div>
        {sourceError && (
          <div className="border-t border-sev-high/20 bg-sev-high/5 px-5 py-2 text-xs text-sev-high">
            Failed to switch source: {sourceError}
          </div>
        )}
      </header>

      <main className="mx-auto max-w-[1440px] space-y-6 px-5 py-6 lg:px-8 lg:py-8">
        {view === 'cases' && !selectedCaseId && <CasesView key={`cases-${refreshKey}`} onSelect={openCase} />}
        {view === 'cases' && selectedCaseId && (
          <CaseDetail caseId={selectedCaseId} onBack={() => setSelectedCaseId(null)} onOpenAlert={openAlert} />
        )}

        {view === 'alerts' && (
          <>
            {!selectedAlertId && <StatsOverview stats={stats} />}
            {!selectedAlertId && (
              <ScoringDashboard
                key={`alerts-${refreshKey}`}
                alerts={alerts || []}
                filters={filters}
                onFilter={handleFilter}
                onSelect={openAlert}
              />
            )}
            {selectedAlertId && (
              <AlertDetail
                alertId={selectedAlertId}
                onBack={() => setSelectedAlertId(null)}
                onOpenCase={openCase}
              />
            )}
          </>
        )}
      </main>
    </div>
  )
}
