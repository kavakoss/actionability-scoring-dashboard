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
      <header className="sticky top-0 z-50 border-b border-edge bg-base/95">
        <div className="mx-auto flex h-14 max-w-[1600px] items-center justify-between px-5">
          <div className="flex items-center gap-3">
            <span className="flex h-7 w-7 items-center justify-center rounded border border-edge bg-panel">
              <svg viewBox="0 0 24 24" className="h-4 w-4 text-accent" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M3 12h4l2-5 4 10 2-5h6" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </span>
            <div>
              <h1 className="text-sm font-semibold text-ink">Actionability Scoring</h1>
              <p className="text-2xs text-ink-faint">Wazuh / Sysmon telemetry quality</p>
            </div>
            <nav className="ml-6 flex h-14 items-end gap-1">
              {TABS.map(([value, label]) => (
                <button
                  key={value}
                  onClick={() => {
                    setView(value)
                    setSelectedCaseId(null)
                    setSelectedAlertId(null)
                  }}
                  className={`h-14 border-b-2 px-3 text-xs font-medium transition-colors ${
                    view === value
                      ? 'border-accent text-ink'
                      : 'border-transparent text-ink-faint hover:text-ink-muted'
                  }`}
                >
                  {label}
                </button>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-3">
            {health && (
              <span className="tabular text-2xs text-ink-faint">
                {health.alerts_count} alerts · {health.cases_count} cases
              </span>
            )}
            <div className="flex items-center rounded border border-edge bg-panel p-0.5">
              {['mock', 'live'].map((source) => (
                <button
                  key={source}
                  disabled={switching || !health}
                  onClick={() => switchSource(source)}
                  className={`rounded-sm px-2 py-0.5 text-2xs font-medium uppercase tracking-wider transition-colors disabled:opacity-40 ${
                    health?.source === source ? 'bg-raised text-ink' : 'text-ink-faint hover:text-ink-muted'
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
          <div className="border-t border-sev-high/30 bg-sev-high/10 px-5 py-1.5 text-2xs text-sev-high">
            Failed to switch source: {sourceError}
          </div>
        )}
      </header>

      <main className="mx-auto max-w-[1600px] space-y-4 p-5">
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
