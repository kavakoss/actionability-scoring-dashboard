import { useState, useEffect } from 'react'
import { fetchTimeline } from '../api'

export default function TimelineView({ alerts, seedId, onSelectSeed }) {
  const [timeline, setTimeline] = useState(null)
  const [selectedSeed, setSelectedSeed] = useState(seedId)

  useEffect(() => {
    if (selectedSeed) {
      fetchTimeline(selectedSeed).then(setTimeline)
    }
  }, [selectedSeed])

  useEffect(() => {
    if (seedId && seedId !== selectedSeed) {
      setSelectedSeed(seedId)
    }
  }, [seedId])

  const mitreColors = {
    'T1059.001': 'border-l-violet-500',
    'T1059.003': 'border-l-cyan-500',
    'T1105': 'border-l-rose-500',
  }

  const mitreBg = {
    'T1059.001': 'bg-violet-500/10',
    'T1059.003': 'bg-cyan-500/10',
    'T1105': 'bg-rose-500/10',
  }

  const levelBadge = (level) => {
    const colors = {
      Low: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      Medium: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      High: 'bg-red-500/20 text-red-300 border-red-500/30',
    }
    return `px-2 py-0.5 rounded text-xs font-medium border ${colors[level] || ''}`
  }

  return (
    <div>
      {/* Seed Alert Selector */}
      <div className="glass rounded-xl p-4 mb-6">
        <label className="text-sm text-slate-400 block mb-2">Select Seed Alert (starting point for timeline reconstruction):</label>
        <select
          value={selectedSeed || ''}
          onChange={e => setSelectedSeed(e.target.value)}
          className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200"
        >
          <option value="">-- Choose a seed alert --</option>
          {alerts.map(a => {
            const m = a.mitre || {}
            const s = a.scoring || {}
            return (
              <option key={a.id} value={a.id}>
                [{s.level}] {m.technique} — {new Date(a.timestamp).toLocaleString()} — {a.agent}
              </option>
            )
          })}
        </select>
      </div>

      {/* Timeline Visualization */}
      {!timeline && (
        <div className="glass rounded-xl p-12 text-center">
          <p className="text-slate-400 text-lg">Select a seed alert to reconstruct attack timeline</p>
          <p className="text-slate-500 text-sm mt-1">
            The system will traverse the correlation graph using BFS to find all connected events
          </p>
        </div>
      )}

      {timeline && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Timeline */}
          <div className="lg:col-span-2">
            <h3 className="text-sm font-bold text-slate-300 mb-4">
              Attack Timeline — {timeline.nodes?.length || 0} events connected
            </h3>

            {(!timeline.nodes || timeline.nodes.length === 0) && (
              <p className="text-slate-500">No connected events found for this seed alert.</p>
            )}

            <div className="timeline-line pl-12 space-y-4">
              {timeline.nodes?.map((node, idx) => {
                const m = node.mitre || {}
                const s = node.scoring || {}
                const color = mitreColors[m.technique] || 'border-l-slate-600'
                const bg = mitreBg[m.technique] || 'bg-slate-800'

                return (
                  <div key={node.id} className="relative">
                    {/* Dot */}
                    <div className={`absolute -left-[34px] top-4 w-5 h-5 rounded-full border-2 border-slate-700 ${bg} ${
                      node.id === selectedSeed ? 'ring-2 ring-amber-400' : ''
                    }`} />

                    {/* Card */}
                    <div className={`glass border-l-4 ${color} rounded-lg p-4 ${
                      node.id === selectedSeed ? 'ring-1 ring-amber-500/50' : ''
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-mono text-slate-400">
                          {new Date(node.timestamp).toLocaleString()}
                        </span>
                        <span className={levelBadge(s.level)}>{s.level}</span>
                      </div>
                      <p className="text-sm font-bold text-white">
                        {m.name || m.technique || 'Unknown Technique'}
                      </p>
                      <p className="text-xs text-slate-400 mt-1">
                        Agent: {node.agent} · Rule: {(node.rule || {}).description || '-'}
                      </p>
                      <p className="text-xs text-slate-500 mt-1 truncate">
                        {(node.summary || '').substring(0, 100)}
                      </p>
                      {node.id === selectedSeed && (
                        <span className="inline-block mt-2 text-xs text-amber-400 font-medium">
                          ★ Seed Alert
                        </span>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Edge / Correlation Info */}
          <div className="lg:col-span-1">
            <h3 className="text-sm font-bold text-slate-300 mb-4">Correlation Edges</h3>
            <div className="glass rounded-xl p-4 space-y-2">
              {(!timeline.edges || timeline.edges.length === 0) && (
                <p className="text-sm text-slate-500">No correlation edges found.</p>
              )}
              {timeline.edges?.map((edge, idx) => (
                <div key={idx} className="flex items-center justify-between text-xs py-2 border-b border-slate-800/50 last:border-0">
                  <span className="text-slate-400 font-mono">
                    {edge.source?.substring(0, 12)}... ↔ {edge.target?.substring(0, 12)}...
                  </span>
                  <span className={`font-bold ${
                    edge.weight >= 90 ? 'text-emerald-400'
                    : edge.weight >= 60 ? 'text-amber-400'
                    : 'text-slate-500'
                  }`}>
                    +{edge.weight}
                  </span>
                </div>
              ))}
            </div>

            {/* Legend */}
            <h3 className="text-sm font-bold text-slate-300 mt-6 mb-3">MITRE ATT&CK Legend</h3>
            <div className="glass rounded-xl p-3 space-y-2 text-xs">
              {[
                { tech: 'T1059.001', name: 'PowerShell', color: 'bg-violet-500' },
                { tech: 'T1059.003', name: 'CMD', color: 'bg-cyan-500' },
                { tech: 'T1105', name: 'Ingress Transfer', color: 'bg-rose-500' },
              ].map(t => (
                <div key={t.tech} className="flex items-center gap-2">
                  <span className={`w-3 h-3 rounded-full ${t.color}`} />
                  <span className="text-slate-300">{t.tech}</span>
                  <span className="text-slate-500">— {t.name}</span>
                </div>
              ))}
              <hr className="border-slate-700/50 my-1" />
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full ring-2 ring-amber-400 bg-slate-700" />
                <span className="text-slate-300">Seed Alert</span>
                <span className="text-slate-500">— Starting point</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
