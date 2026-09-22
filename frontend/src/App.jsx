import { useEffect, useState } from 'react'
import CasesView from './components/CasesView'
import CaseDetail from './components/CaseDetail'
import ScoringDashboard from './components/ScoringDashboard'
import AlertDetail from './components/AlertDetail'
import StatsOverview from './components/StatsOverview'
import { fetchAlerts, fetchHealth, fetchStats } from './api'
import { Badge } from './components/ui'

const TABS = [
  ['cases', 'Cases'],
  ['alerts', 'Alerts'],
]

export default function App() {
  const [view, setView] = useState('cases')
  const [selectedCaseId, setSelectedCaseId] = useState(null)
  const [selectedAlertId, setSelectedAlertId] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [health, setHealth] = useState(null)
  const [filters, setFilters] = useState({})

  useEffect(() => {
    fetchHealth().then(setHealth).catch(() => setHealth(null))
  }, [])

  useEffect(() => {
    fetchAlerts(filters).then((data) => setAlerts(data.alerts || []))
    fetchStats().then(setStats)
  }, [filters])

  const handleFilter = (key, value) => {
    setFilters((prev) => {
      const next = { ...prev }
      if (value) next[key] = value
      else delete next[key]
      return next
    })
  }

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
      <header className="sticky top-0 z-50 border-b border-edge bg-base/95 backdrop-blur-[2px]">
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
          <div className="flex items-center gap-2">
            {health && (
              <Badge className={health.mode === 'live' ? 'border-sev-low/40 text-sev-low' : 'border-edge text-ink-faint'}>
                {health.mode === 'live' ? 'LIVE' : 'MOCK'}
              </Badge>
            )}
            {health && (
              <span className="tabular text-2xs text-ink-faint">
                {health.alerts_count} alerts · {health.cases_count} cases
              </span>
            )}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1600px] space-y-4 p-5">
        {view === 'cases' && !selectedCaseId && <CasesView onSelect={openCase} />}
        {view === 'cases' && selectedCaseId && (
          <CaseDetail caseId={selectedCaseId} onBack={() => setSelectedCaseId(null)} onOpenAlert={openAlert} />
        )}

        {view === 'alerts' && (
          <>
            {!selectedAlertId && <StatsOverview stats={stats} />}
            {!selectedAlertId && (
              <ScoringDashboard
                alerts={alerts}
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
