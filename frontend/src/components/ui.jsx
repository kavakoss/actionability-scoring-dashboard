export const TECH_LABELS = {
  'T1059.001': 'PowerShell',
  'T1059.003': 'Command Shell',
  T1105: 'Ingress Transfer',
}
const TECHNIQUES = {
  'T1059.001': { text: 'text-tech-pwsh', dot: 'bg-tech-pwsh' },
  'T1059.003': { text: 'text-tech-cmd', dot: 'bg-tech-cmd' },
  T1105: { text: 'text-tech-transfer', dot: 'bg-tech-transfer' },
}
export const techniqueStyle = (technique) =>
  TECHNIQUES[technique] || { text: 'text-ink-muted', dot: 'bg-ink-faint' }
export const bandText = (level) =>
  ({
    High: 'text-band-high',
    Medium: 'text-band-medium',
    Low: 'text-band-low',
  })[level] || 'text-ink-muted'
export const levelTone = (level) =>
  ({ High: 'bg-band-high', Medium: 'bg-band-medium', Low: 'bg-band-low' })[
    level
  ] || 'bg-ink-faint'
export function Panel({ children, className = '', ...props }) {
  return (
    <section
      className={`min-w-0 rounded-xl border border-edge bg-panel ${className}`}
      {...props}
    >
      {children}
    </section>
  )
}
export function SectionTitle({ children, right, description }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-edge px-5 py-4">
      <div>
        <h2 className="text-heading font-semibold">{children}</h2>
        {description && (
          <p className="mt-1 text-small text-ink-muted">{description}</p>
        )}
      </div>
      {right}
    </div>
  )
}
export function Badge({ children, className = '' }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded border border-edge px-1.5 py-0.5 text-caption font-medium text-ink-muted ${className}`}
    >
      {children}
    </span>
  )
}
export function LevelBadge({ level, className = '' }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-caption font-medium ${bandText(level)} ${className}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${levelTone(level)}`}
        aria-hidden="true"
      />
      {level || 'Unscored'}
    </span>
  )
}
export function WazuhBadge({ level }) {
  return <Badge>L{level ?? '—'}</Badge>
}
export function TechniqueTag({ technique, label, className = '' }) {
  const style = techniqueStyle(technique)
  return (
    <span
      className={`inline-flex min-w-0 items-center gap-2 text-small font-medium ${style.text} ${className}`}
    >
      <span
        className={`h-1.5 w-1.5 shrink-0 rounded-full ${style.dot}`}
        aria-hidden="true"
      />
      {label || technique || 'Unknown'}
    </span>
  )
}
export function Meter({
  value,
  max = 100,
  tone = 'bg-ink-faint',
  height = 'h-1',
  className = '',
  label,
}) {
  const width =
    max > 0 ? Math.min(100, Math.max(0, (Number(value) / max) * 100)) : 0
  return (
    <div
      role={label ? 'meter' : undefined}
      aria-label={label}
      aria-valuenow={label ? Number(value) : undefined}
      aria-valuemin={label ? 0 : undefined}
      aria-valuemax={label ? max : undefined}
      aria-hidden={label ? undefined : true}
      className={`overflow-hidden rounded-full bg-edge ${height} ${className}`}
    >
      <div
        className={`score-bar h-full rounded-full ${tone}`}
        style={{ width: `${width}%` }}
      />
    </div>
  )
}
export function ScoreCell({ score, level }) {
  return (
    <div className="ml-auto w-full max-w-[132px] min-w-0">
      <div className="mb-2 flex items-baseline justify-between gap-2">
        <LevelBadge level={level} />
        <span className="font-semibold text-ink">
          {score ?? '—'}
          <span className="text-caption font-normal text-ink-faint"> /100</span>
        </span>
      </div>
      <Meter value={score} tone={levelTone(level)} />
    </div>
  )
}
export function ScoreCard({
  label = 'Actionability',
  score,
  level,
  covered,
  total,
  coverageLabel = 'Expected fields present',
}) {
  return (
    <aside className="border-t border-edge bg-raised/50 p-6 lg:w-[292px] lg:shrink-0 lg:border-l lg:border-t-0">
      <p className="text-small font-medium text-ink-muted">{label}</p>
      <div className="my-3 flex items-end justify-between gap-4">
        <p className="text-[44px] font-semibold leading-none tracking-tight">
          {score ?? '—'}
          <span className="ml-1 text-heading font-normal text-ink-faint">
            /100
          </span>
        </p>
        <LevelBadge level={level} />
      </div>
      <Meter value={score} tone={levelTone(level)} className="mt-4" />
      <div className="mt-5 flex justify-between gap-3 text-small">
        <span className="text-ink-muted">{coverageLabel}</span>
        <strong className="font-medium">
          {covered}/{total}
        </strong>
      </div>
      <p className="mt-3 text-caption leading-5 text-ink-faint">
        Evidence completeness for this technique, not threat severity.
      </p>
    </aside>
  )
}
export function Dot({ on, tone }) {
  return (
    <span
      aria-hidden="true"
      className={`inline-block h-1.5 w-1.5 shrink-0 rounded-full ${tone || (on ? 'bg-ink-muted' : 'bg-edge-strong')}`}
    />
  )
}
export function EmptyState({ title, hint }) {
  return (
    <div className="px-5 py-14 text-center">
      <p className="text-heading font-medium">{title}</p>
      {hint && (
        <p className="mx-auto mt-2 max-w-lg text-small text-ink-muted">
          {hint}
        </p>
      )}
    </div>
  )
}
export function SkeletonRows({ rows = 5, className = '' }) {
  return (
    <div
      role="status"
      aria-label="Loading data"
      className={`divide-y divide-edge p-5 ${className}`}
    >
      <span className="sr-only">Loading data</span>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex animate-pulse gap-8 py-4">
          <span className="h-4 w-1/3 rounded bg-raised" />
          <span className="h-4 w-1/5 rounded bg-raised" />
          <span className="ml-auto h-4 w-1/6 rounded bg-raised" />
        </div>
      ))}
    </div>
  )
}
export const Skeleton = SkeletonRows
export function Spinner({ className = '' }) {
  return (
    <span
      role="status"
      aria-label="Loading"
      className={`inline-block h-3 w-3 animate-spin rounded-full border border-ink-faint border-t-transparent ${className}`}
    />
  )
}
export function KeyValue({ label, children, mono = false }) {
  return (
    <div className="min-w-0">
      <dt className="text-caption text-ink-faint">{label}</dt>
      <dd
        className={`mt-1 text-small text-ink ${mono ? 'break-all font-mono text-caption' : ''}`}
      >
        {children}
      </dd>
    </div>
  )
}
export function FilterSelect({ label, value, onChange, children }) {
  return (
    <label className="flex items-center gap-2">
      <span className="sr-only">{label}</span>
      <select
        aria-label={label}
        value={value}
        onChange={onChange}
        className="filter-select"
      >
        {children}
      </select>
    </label>
  )
}
export function Filters({ kind, filters, onChange }) {
  return (
    <div className="flex flex-wrap gap-2">
      <FilterSelect
        label={`Filter ${kind} by technique`}
        value={filters.technique || ''}
        onChange={(e) => onChange('technique', e.target.value)}
      >
        <option value="">All techniques</option>
        {Object.entries(TECH_LABELS).map(([id, label]) => (
          <option key={id} value={id}>
            {id} · {label}
          </option>
        ))}
      </FilterSelect>
      <FilterSelect
        label={`Filter ${kind} by actionability`}
        value={filters.level || ''}
        onChange={(e) => onChange('level', e.target.value)}
      >
        <option value="">All bands</option>
        {['High', 'Medium', 'Low'].map((level) => (
          <option key={level}>{level}</option>
        ))}
      </FilterSelect>
    </div>
  )
}
export function shortId(id, length = 14) {
  return !id ? '—' : id.length > length ? `${id.slice(0, length)}…` : id
}
export function formatTime(value, timeOnly = false) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: 'UTC',
    ...(timeOnly ? {} : { day: '2-digit', month: 'short' }),
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date)
}
