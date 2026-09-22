const TECHNIQUE_STYLE = {
  'T1059.001': { border: 'border-tech-pwsh/60', text: 'text-tech-pwsh', dot: 'bg-tech-pwsh' },
  'T1059.003': { border: 'border-tech-cmd/60', text: 'text-tech-cmd', dot: 'bg-tech-cmd' },
  'T1105': { border: 'border-tech-transfer/60', text: 'text-tech-transfer', dot: 'bg-tech-transfer' },
}

export const techniqueStyle = (technique) =>
  TECHNIQUE_STYLE[technique] || { border: 'border-edge', text: 'text-ink-muted', dot: 'bg-ink-faint' }

const LEVEL_TONE = {
  Low: 'text-sev-low border-sev-low/40',
  Medium: 'text-sev-medium border-sev-medium/40',
  High: 'text-sev-high border-sev-high/40',
}

export function Panel({ children, className = '' }) {
  return (
    <section className={`rounded-md border border-edge bg-panel ${className}`}>{children}</section>
  )
}

export function SectionTitle({ children, right }) {
  return (
    <div className="flex items-center justify-between border-b border-edge px-4 py-2.5">
      <h2 className="text-2xs font-semibold uppercase tracking-wider text-ink-muted">{children}</h2>
      {right}
    </div>
  )
}

export function Badge({ children, className = '' }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-2xs font-medium ${className}`}
    >
      {children}
    </span>
  )
}

export function LevelBadge({ level, className = '' }) {
  return <Badge className={`${LEVEL_TONE[level] || 'text-ink-muted border-edge'} ${className}`}>{level}</Badge>
}

export function TechniqueTag({ technique, label, className = '' }) {
  const style = techniqueStyle(technique)
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs ${style.text} ${className}`}>
      <span className={`h-1.5 w-1.5 rounded-sm ${style.dot}`} />
      {label || technique || 'Unknown'}
    </span>
  )
}

export function Meter({ value, max = 100, tone = 'bg-accent', height = 'h-1.5', className = '' }) {
  const width = max > 0 ? Math.min(100, Math.max(0, (value / max) * 100)) : 0
  return (
    <div className={`w-full overflow-hidden rounded-sm bg-edge ${height} ${className}`}>
      <div className={`h-full rounded-sm ${tone} score-bar`} style={{ width: `${width}%` }} />
    </div>
  )
}

export function levelTone(level) {
  if (level === 'High') return 'bg-sev-high'
  if (level === 'Medium') return 'bg-sev-medium'
  return 'bg-sev-low'
}

export function Dot({ on, tone }) {
  const color = tone || (on ? 'bg-accent' : 'bg-edge')
  return <span className={`inline-block h-2 w-2 rounded-sm ${color}`} />
}

export function EmptyState({ title, hint }) {
  return (
    <div className="px-4 py-10 text-center">
      <p className="text-sm text-ink-muted">{title}</p>
      {hint && <p className="mt-1 text-xs text-ink-faint">{hint}</p>}
    </div>
  )
}

export function KeyValue({ label, children, mono = false }) {
  return (
    <div>
      <dt className="text-2xs uppercase tracking-wider text-ink-faint">{label}</dt>
      <dd className={`mt-0.5 text-xs text-ink ${mono ? 'font-mono' : ''}`}>{children}</dd>
    </div>
  )
}

export function shortId(id, length = 14) {
  if (!id) return '-'
  return id.length > length ? `${id.slice(0, length)}…` : id
}
