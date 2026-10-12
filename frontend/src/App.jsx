import { useCallback, useEffect, useState } from 'react'
import CasesView from './components/CasesView'
import CaseDetail from './components/CaseDetail'
import ScoringDashboard from './components/ScoringDashboard'
import AlertDetail from './components/AlertDetail'
import StatsOverview from './components/StatsOverview'
import { fetchAlerts, fetchHealth, fetchStats, setSource } from './api'
import { Spinner, formatTime } from './components/ui'

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
  const [statsError, setStatsError] = useState(null)
  const [health, setHealth] = useState(null)
  const [filters, setFilters] = useState({})
  const [switching, setSwitching] = useState(false)
  const [sourceError, setSourceError] = useState(null)
  const [dataError, setDataError] = useState(null)
  const [refreshKey, setRefreshKey] = useState(0)
  const quality = health?.data_quality || {}
  const config = health?.config || {}
  const liveWindow =
    config.live_from && config.live_to
      ? `${formatTime(config.live_from)} – ${formatTime(config.live_to)} UTC`
      : `Last ${config.live_hours_back ?? 48} hours`
  const windowTitle =
    config.live_from && config.live_to
      ? `${config.live_from} → ${config.live_to}`
      : liveWindow

  useEffect(() => {
    const params = new URLSearchParams()
    params.set('view', view)
    if (selectedCaseId) params.set('case', selectedCaseId)
    if (selectedAlertId) params.set('alert', selectedAlertId)
    window.history.replaceState(null, '', `?${params}`)
  }, [view, selectedCaseId, selectedAlertId])

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch(() =>
        setSourceError('The API is unavailable. Check the backend connection.'),
      )
  }, [refreshKey])
  useEffect(() => {
    let active = true
    setAlerts(null)
    setDataError(null)
    setStatsError(null)
    fetchAlerts(filters)
      .then((data) => {
        if (active) setAlerts(data.alerts || [])
      })
      .catch(() => {
        if (active) setDataError('Unable to load alerts. Please retry.')
      })
    fetchStats()
      .then((data) => {
        if (active) setStats(data)
      })
      .catch(() => {
        if (active) {
          setStats(null)
          setStatsError('Unable to load the overview statistics.')
        }
      })
    return () => {
      active = false
    }
  }, [filters, refreshKey])

  const handleFilter = (key, value) =>
    setFilters((prev) => {
      const next = { ...prev }
      if (value) next[key] = value
      else delete next[key]
      return next
    })
  const switchSource = useCallback(
    async (source) => {
      if (!health || health.source === source || switching) return
      setSwitching(true)
      setSourceError(null)
      try {
        setHealth(await setSource(source))
        setSelectedCaseId(null)
        setSelectedAlertId(null)
        setAlerts(null)
        setStats(null)
        setRefreshKey((key) => key + 1)
      } catch (error) {
        setSourceError(String(error.message || error))
      } finally {
        setSwitching(false)
      }
    },
    [health, switching],
  )
  const navigate = (next) => {
    setView(next)
    setSelectedCaseId(null)
    setSelectedAlertId(null)
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
      <a
        href="#main"
        className="sr-only z-[100] rounded bg-panel p-3 text-accent focus:not-sr-only focus:fixed focus:left-4 focus:top-4"
      >
        Skip to content
      </a>
      <header className="sticky top-0 z-40 border-b border-edge bg-panel">
        <div className="mx-auto flex min-h-[78px] max-w-[1600px] items-center justify-between gap-4 px-4 sm:px-6 lg:px-8">
          <div className="flex min-w-0 items-center gap-3">
            <span
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-edge-strong text-ink"
              aria-hidden="true"
            >
              <svg
                viewBox="0 0 24 24"
                className="h-5 w-5"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
              >
                <path d="M5 4v16M11 8v12M17 12v8M3 20h18" />
              </svg>
            </span>
            <div>
              <p className="text-heading font-semibold tracking-tight">
                Actionability<span className="hidden sm:inline"> Scoring</span>
              </p>
              <p className="hidden text-caption text-ink-faint sm:block">
                Wazuh / Sysmon · Evidence completeness
              </p>
            </div>
          </div>
          <div className="flex min-w-0 items-center gap-4 lg:gap-6">
            <div
              className="hidden max-w-[440px] text-right text-caption lg:block"
              title={`${windowTitle}. Seeds: Wazuh level ≥ ${config.seed_min_level}. ${quality.excluded_known_benign_count ?? 0} known-benign excluded.`}
            >
              <p className="truncate text-ink-muted">
                {health?.source === 'live'
                  ? liveWindow
                  : 'Deterministic sample data'}
              </p>
              <p className="mt-1 text-ink-faint">
                {health?.source === 'live'
                  ? `Seed threshold ≥ L${config.seed_min_level} · ${quality.raw_candidates_count ?? 0} candidates`
                  : 'Mock source · No live telemetry'}
              </p>
            </div>
            <div className="flex items-center gap-2" aria-busy={switching}>
              <div
                className="inline-flex shrink-0 rounded-lg border border-edge bg-base p-1"
                aria-label="Data source"
              >
                {['mock', 'live'].map((source) => (
                  <button
                    key={source}
                    disabled={switching || !health}
                    aria-pressed={health?.source === source}
                    onClick={() => switchSource(source)}
                    className={`rounded-md px-3 py-1.5 text-caption font-semibold uppercase tracking-wide transition-colors disabled:opacity-50 ${health?.source === source ? 'bg-raised text-ink' : 'text-ink-faint hover:text-ink'}`}
                  >
                    {source}
                  </button>
                ))}
              </div>
              {switching && <Spinner />}
            </div>
          </div>
        </div>
        <div className="mx-auto flex max-w-[1600px] items-center justify-between gap-4 px-4 sm:px-6 lg:px-8">
          <nav className="flex gap-7" aria-label="Main navigation">
            {[
              ['cases', 'Cases'],
              ['alerts', 'Alerts'],
            ].map(([key, label]) => (
              <button
                key={key}
                aria-current={view === key ? 'page' : undefined}
                onClick={() => navigate(key)}
                className={`border-b-2 py-3 text-small font-medium transition-colors ${view === key ? 'border-accent text-ink' : 'border-transparent text-ink-muted hover:text-ink'}`}
              >
                {label}
              </button>
            ))}
          </nav>
          <span
            className="truncate text-caption text-ink-faint"
            title={
              health?.source === 'live'
                ? `${windowTitle} · Seed threshold ≥ L${config.seed_min_level ?? 15}`
                : 'Deterministic sample data · Mock source'
            }
          >
            {switching
              ? 'Loading source…'
              : health
                ? `${health.source.toUpperCase()} · ${health.alerts_count} alerts · ${health.cases_count} cases`
                : 'Connecting…'}
          </span>
        </div>
      </header>
      <main
        id="main"
        className="mx-auto max-w-[1600px] space-y-6 px-4 py-7 sm:px-6 lg:px-8 lg:py-8"
      >
        {(sourceError || health?.last_error) && (
          <div role="alert" className="notice">
            {sourceError || health.last_error}
          </div>
        )}
        {health?.source === 'live' &&
          (quality.query_capped ||
            quality.omitted_due_to_display_limit > 0) && (
            <p className="notice">
              This view is limited: {quality.omitted_due_to_display_limit ?? 0}{' '}
              eligible alerts omitted.
              {quality.query_capped ? ' The query limit was reached.' : ''}
            </p>
          )}
        {view === 'cases' && !selectedCaseId && (
          <CasesView key={`cases-${refreshKey}`} onSelect={openCase} />
        )}
        {view === 'cases' && selectedCaseId && (
          <CaseDetail
            caseId={selectedCaseId}
            onBack={() => setSelectedCaseId(null)}
            onOpenAlert={openAlert}
          />
        )}
        {view === 'alerts' && !selectedAlertId && (
          <>
            <StatsOverview stats={stats} error={statsError} />
            <ScoringDashboard
              alerts={alerts}
              filters={filters}
              onFilter={handleFilter}
              onSelect={openAlert}
              error={dataError}
            />
          </>
        )}
        {view === 'alerts' && selectedAlertId && (
          <AlertDetail
            alertId={selectedAlertId}
            onBack={() => setSelectedAlertId(null)}
            onOpenCase={openCase}
          />
        )}
        <footer className="flex flex-wrap justify-between gap-2 border-t border-edge pt-5 text-caption text-ink-faint">
          <span>
            Actionability measures evidence completeness. Wazuh rule levels are
            shown separately.
          </span>
          <span>All event times in UTC</span>
        </footer>
      </main>
    </div>
  )
}
