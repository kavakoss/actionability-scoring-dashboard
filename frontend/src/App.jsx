import { useState, useEffect } from 'react'
import StatsOverview from './components/StatsOverview'
import ScoringDashboard from './components/ScoringDashboard'
import AlertDetail from './components/AlertDetail'
import TimelineView from './components/TimelineView'
import { fetchAlerts, fetchStats } from './api'

export default function App() {
  const [view, setView] = useState('dashboard')
  const [selectedAlertId, setSelectedAlertId] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [filters, setFilters] = useState({})

  useEffect(() => {
    fetchAlerts(filters).then(d => setAlerts(d.alerts || d))
    fetchStats().then(setStats)
  }, [filters])

  const handleFilter = (key, value) => {
    setFilters(prev => {
      const next = { ...prev }
      if (value) next[key] = value
      else delete next[key]
      return next
    })
  }

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header */}
      <header className="glass sticky top-0 z-50 border-b border-slate-700/50 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-amber-400">
              ⚡ Actionability Scoring Dashboard
            </h1>
            <p className="text-sm text-slate-400">
              Wazuh SIEM · MITRE ATT&CK · Graph Correlation
            </p>
          </div>
          <nav className="flex gap-2">
            {[
              ['dashboard', '📊 Dashboard'],
              ['timeline', '🕐 Timeline'],
            ].map(([v, label]) => (
              <button
                key={v}
                onClick={() => { setView(v); setSelectedAlertId(null) }}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
                  view === v
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto p-6">
        {stats && <StatsOverview stats={stats} />}

        {view === 'dashboard' && !selectedAlertId && (
          <ScoringDashboard
            alerts={alerts}
            filters={filters}
            onFilter={handleFilter}
            onSelect={id => setSelectedAlertId(id)}
          />
        )}

        {view === 'dashboard' && selectedAlertId && (
          <AlertDetail
            alertId={selectedAlertId}
            onBack={() => setSelectedAlertId(null)}
            onShowTimeline={id => { setSelectedAlertId(id); setView('timeline') }}
          />
        )}

        {view === 'timeline' && (
          <TimelineView
            alerts={alerts}
            seedId={selectedAlertId}
            onSelectSeed={id => setSelectedAlertId(id)}
          />
        )}
      </main>
    </div>
  )
}
