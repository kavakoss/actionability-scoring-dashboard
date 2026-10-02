const TECHNIQUE_STYLE = {
  'T1059.001': { border: 'border-tech-pwsh/60', text: 'text-tech-pwsh', dot: 'bg-tech-pwsh' },
  'T1059.003': { border: 'border-tech-cmd/60', text: 'text-tech-cmd', dot: 'bg-tech-cmd' },
  'T1105': { border: 'border-tech-transfer/60', text: 'text-tech-transfer', dot: 'bg-tech-transfer' },
}

export const techniqueStyle = (technique) =>
  TECHNIQUE_STYLE[technique] || { border: 'border-edge', text: 'text-ink-muted', dot: 'bg-ink-faint' }

const LEVEL_TONE = {
  Low: 'bg-band-low/10 text-band-low border-band-low/30',
  Medium: 'bg-band-medium/10 text-band-medium border-band-medium/30',
  High: 'bg-band-high/10 text-band-high border-band-high/30',
}

export function Panel({ children, className = '' }) {
  return (
    <section className={`rounded-xl border border-edge bg-panel ${className}`}>{children}</section>
  )
}

export function SectionTitle({ children, right }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-edge px-5 py-3">
      <h2 className="text-sm font-semibold tracking-normal text-ink">{children}</h2>
      {right}
    </div>
  )
}

export function Badge({ children, className = '' }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs font-medium ${className}`}
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
    <span className={`inline-flex items-center gap-2 text-xs font-medium ${style.text} ${className}`}>
      <span className={`h-2 w-2 rounded-full ${style.dot}`} />
      {label || technique || 'Unknown'}
    </span>
  )
}

export function Meter({ value, max = 100, tone = 'bg-accent', height = 'h-1.5', className = '' }) {
  const width = max > 0 ? Math.min(100, Math.max(0, (value / max) * 100)) : 0
  return (
    <div className={`w-full overflow-hidden rounded-full bg-edge ${height} ${className}`}>
      <div className={`h-full rounded-full ${tone} score-bar`} style={{ width: `${width}%` }} />
    </div>
  )
}

export function levelTone(level) {
  if (level === 'High') return 'bg-band-high'
  if (level === 'Medium') return 'bg-band-medium'
  return 'bg-band-low'
}

export function Dot({ on, tone }) {
  const color = tone || (on ? 'bg-accent' : 'bg-edge')
  return <span className={`inline-block h-2 w-2 rounded-full ${color}`} />
}

export function EmptyState({ title, hint }) {
  return (
    <div className="px-4 py-10 text-center">
      <p className="text-sm text-ink-muted">{title}</p>
      {hint && <p className="mt-1 text-xs text-ink-faint">{hint}</p>}
    </div>
  )
}

export function SkeletonRows({ rows = 5, className = '' }) {
  return (
    <div className={`space-y-2 p-4 ${className}`}>
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="h-7 animate-pulse rounded-md bg-raised" />
      ))}
    </div>
  )
}

export function Spinner({ className = '' }) {
  return (
    <span
      className={`inline-block h-3 w-3 animate-spin rounded-full border border-ink-faint border-t-transparent ${className}`}
    />
  )
}

export function KeyValue({ label, children, mono = false }) {
  return (
    <div>
      <dt className="text-xs font-medium text-ink-muted">{label}</dt>
      <dd className={`mt-1 text-sm text-ink ${mono ? 'font-mono tabular' : ''}`}>{children}</dd>
    </div>
  )
}

export function shortId(id, length = 14) {
  if (!id) return '-'
  return id.length > length ? `${id.slice(0, length)}…` : id
}
