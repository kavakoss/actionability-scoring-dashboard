import { useState, useEffect } from 'react'
import { fetchAlertDetail } from '../api'

const catColors = {
  identity: '#8b5cf6',
  behavioral: '#ec4899',
  relationship: '#f59e0b',
  ioc: '#06b6d4',
  network: '#10b981',
  timeline: '#6b7280',
}

export default function AlertDetail({ alertId, onBack, onShowTimeline }) {
  const [detail, setDetail] = useState(null)

  useEffect(() => {
    fetchAlertDetail(alertId).then(setDetail)
  }, [alertId])

  if (!detail) return <p className="text-slate-400 text-center py-12">Loading...</p>

  const s = detail.scoring
  const m = detail.mitre
  const r = detail.rule

  return (
    <div>
      <button
        onClick={onBack}
        className="mb-4 text-sm text-amber-400 hover:text-amber-300 transition"
      >
        ← Back to alerts
      </button>

      {/* Alert Summary */}
      <div className="glass rounded-xl p-6 mb-6">
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <h2 className="text-lg font-bold text-white">{m.name} ({m.technique})</h2>
            <p className="text-sm text-slate-400 mt-1">{r.description}</p>
            <div className="flex gap-3 mt-3 text-xs">
              <span className="text-slate-400">Agent: <span className="text-slate-200">{detail.agent?.name}</span></span>
              <span className="text-slate-400">Tactic: <span className="text-slate-200">{m.tactic}</span></span>
              <span className="text-slate-400">Rule Level: <span className="text-slate-200">{r.level}</span></span>
              <span className="text-slate-400">Time: <span className="text-slate-200 font-mono">{new Date(detail.timestamp).toLocaleString()}</span></span>
            </div>
          </div>

          <div className="text-right">
            <p className="text-4xl font-bold text-white">{s.total_score}</p>
            <p className="text-sm text-slate-400">of {s.max_score} max</p>
            <span className={`inline-block mt-2 px-3 py-1 rounded-full text-sm font-bold ${
              s.level === 'High' ? 'bg-red-500/20 text-red-300 border border-red-500/30'
              : s.level === 'Medium' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
            }`}>
              {s.level} Actionability ({s.percentage}%)
            </span>
          </div>
        </div>

        <button
          onClick={() => onShowTimeline(alertId)}
          className="mt-4 px-4 py-2 bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-lg text-sm font-medium hover:bg-amber-500/30 transition"
        >
          🕐 View Attack Timeline →
        </button>
      </div>

      {/* Category Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {Object.entries(s.categories || {}).map(([key, cat]) => (
          <div key={key} className="glass rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-white">{cat.label}</h3>
              <span className="text-sm font-mono text-slate-300">
                {cat.score}/{cat.max} ({cat.percentage}%)
              </span>
            </div>

            {/* Progress bar */}
            <div className="w-full h-2 bg-slate-700 rounded-full mb-3 overflow-hidden">
              <div
                className="h-full rounded-full score-bar"
                style={{
                  width: `${cat.percentage}%`,
                  backgroundColor: catColors[key] || '#6b7280',
                }}
              />
            </div>

            {/* Field details */}
            <div className="space-y-2">
              {cat.fields?.map(field => (
                <div key={field.field} className="text-xs">
                  <div className="flex items-center justify-between">
                    <span className={`${field.present ? 'text-slate-200' : 'text-slate-600'}`}>
                      {field.present ? '✓' : '✗'} {field.field}
                      <span className="text-slate-500 ml-1">
                        (AHP {field.weight})
                      </span>
                    </span>
                    {field.present && field.value && (
                      <span className="text-slate-400 font-mono ml-2 truncate max-w-[180px]" title={field.value}>
                        {field.value}
                      </span>
                    )}
                  </div>
                  {field.mitre_relationship && (
                    <div className="text-[10px] text-slate-600 mt-0.5 ml-5">
                      MITRE: {field.mitre_relationship} · {field.ahp_level}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
