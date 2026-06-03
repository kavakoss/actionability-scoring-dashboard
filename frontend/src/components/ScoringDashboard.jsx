export default function ScoringDashboard({ alerts, filters, onFilter, onSelect }) {
  const levelBadge = (level) => {
    const colors = {
      Low: 'bg-red-500/20 text-red-300 border-red-500/30',
      Medium: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      High: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
    }
    return `px-2 py-0.5 rounded text-xs font-medium border ${colors[level] || ''}`
  }

  const techniqueLabel = {
    'T1059.001': { label: 'PowerShell', color: 'text-violet-400' },
    'T1059.003': { label: 'CMD', color: 'text-cyan-400' },
    'T1105': { label: 'Ingress Transfer', color: 'text-rose-400' },
  }

  if (!alerts || alerts.length === 0) {
    return (
      <div className="glass rounded-xl p-8 text-center">
        <p className="text-slate-400 text-lg">No alerts found</p>
        <p className="text-slate-500 text-sm mt-1">Try adjusting filters</p>
      </div>
    )
  }

  return (
    <div>
      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-4">
        <select
          value={filters.technique || ''}
          onChange={e => onFilter('technique', e.target.value)}
          className="bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200"
        >
          <option value="">All Techniques</option>
          <option value="T1059.001">T1059.001 - PowerShell</option>
          <option value="T1059.003">T1059.003 - CMD</option>
          <option value="T1105">T1105 - Ingress Transfer</option>
        </select>
        <select
          value={filters.level || ''}
          onChange={e => onFilter('level', e.target.value)}
          className="bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200"
        >
          <option value="">All Levels</option>
          <option value="Low">Low</option>
          <option value="Medium">Medium</option>
          <option value="High">High</option>
        </select>
      </div>

      {/* Alert Table */}
      <div className="glass rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700/50">
              <th className="text-left p-3 text-slate-400 font-medium">Timestamp</th>
              <th className="text-left p-3 text-slate-400 font-medium">Agent</th>
              <th className="text-left p-3 text-slate-400 font-medium">MITRE Technique</th>
              <th className="text-left p-3 text-slate-400 font-medium">Rule</th>
              <th className="text-left p-3 text-slate-400 font-medium">Score</th>
              <th className="text-left p-3 text-slate-400 font-medium">Level</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map(alert => {
              const s = alert.scoring || {}
              const m = alert.mitre || {}
              const tech = techniqueLabel[m.technique] || { label: m.technique, color: 'text-slate-300' }
              return (
                <tr
                  key={alert.id}
                  onClick={() => onSelect(alert.id)}
                  className="border-b border-slate-800/50 hover:bg-slate-800/50 cursor-pointer transition"
                >
                  <td className="p-3 text-slate-300 font-mono text-xs">
                    {new Date(alert.timestamp).toLocaleString()}
                  </td>
                  <td className="p-3 text-slate-200">{alert.agent}</td>
                  <td className={`p-3 font-medium ${tech.color}`}>{tech.label}</td>
                  <td className="p-3 text-slate-400 max-w-[200px] truncate">
                    {(alert.rule || {}).description || '-'}
                  </td>
                  <td className="p-3">
                    <div className="flex items-center gap-2">
                      <span className="text-white font-bold">{s.total_score}</span>
                      <div className="w-20 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full score-bar ${
                            s.level === 'High' ? 'bg-emerald-500' : s.level === 'Medium' ? 'bg-amber-500' : 'bg-red-500'
                          }`}
                          style={{ width: `${Math.min(s.percentage || 0, 100)}%` }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="p-3">
                    <span className={levelBadge(s.level)}>{s.level}</span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
