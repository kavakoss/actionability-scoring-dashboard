export default function StatsOverview({ stats }) {
  if (!stats) return null

  const { total_alerts, by_level, by_technique } = stats

  const levelColors = { Low: 'bg-red-500', Medium: 'bg-amber-500', High: 'bg-emerald-500' }
  const techColors = {
    'T1059.001': 'bg-violet-500',
    'T1059.003': 'bg-cyan-500',
    'T1105': 'bg-rose-500',
  }

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      {/* Total Alerts */}
      <div className="glass rounded-xl p-4">
        <p className="text-sm text-slate-400">Total Alerts</p>
        <p className="text-3xl font-bold text-white">{total_alerts}</p>
        <p className="text-xs text-slate-500">3 MITRE Techniques</p>
      </div>

      {/* Level Distribution */}
      {Object.entries(by_level).map(([level, count]) => (
        <div key={level} className="glass rounded-xl p-4">
          <p className="text-sm text-slate-400">{level} Actionability</p>
          <div className="flex items-center gap-3 mt-1">
            <span className={`w-3 h-3 rounded-full ${levelColors[level] || 'bg-slate-500'}`} />
            <p className="text-3xl font-bold text-white">{count}</p>
          </div>
          <p className="text-xs text-slate-500">
            {total_alerts > 0 ? Math.round(count / total_alerts * 100) : 0}% of total
          </p>
        </div>
      ))}

      {/* Per-Technique Average Score */}
      {Object.entries(by_technique || {}).map(([tech, data]) => (
        <div key={tech} className="glass rounded-xl p-4">
          <p className="text-sm text-slate-400">{tech}</p>
          <div className="flex items-center gap-2 mt-1">
            <span className={`w-3 h-3 rounded-full ${techColors[tech] || 'bg-slate-500'}`} />
            <p className="text-3xl font-bold text-white">{data.avg_score}</p>
            <span className="text-xs text-slate-400">/ {data.avg_percentage}%</span>
          </div>
          <p className="text-xs text-slate-500">{data.count} alerts</p>
        </div>
      ))}
    </div>
  )
}
