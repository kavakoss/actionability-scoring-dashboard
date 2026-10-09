import { Dot, EmptyState } from './ui'

function FactRow({ fact }) {
  const carriers = fact.carriers || []
  const values = [...new Set(carriers.map((carrier) => String(carrier.value)))]
  return (
    <tr className="row-link">
      <td>
        <div className="flex items-center gap-2">
          <Dot on={fact.completeness === 1} />
          <span className="font-medium">{fact.label}</span>
        </div>
        <p className="mt-1 pl-3.5 font-mono text-caption text-ink-faint">
          {fact.field}
        </p>
        <span className="mt-1 block pl-3.5 text-caption text-ink-muted">
          {fact.completeness === 1 ? 'Present' : 'Missing'}
        </span>
      </td>
      <td className="text-caption capitalize text-ink-muted">{fact.role}</td>
      <td>
        {values.length ? (
          <>
            <div className="space-y-1">
              {values.slice(0, 2).map((value) => (
                <p
                  key={value}
                  className="truncate font-mono text-caption text-ink-muted"
                  title={value}
                >
                  {value}
                </p>
              ))}
            </div>
            <details className="mt-2 text-caption">
              <summary className="cursor-pointer text-accent">
                {values.length} {values.length === 1 ? 'value' : 'values'} ·{' '}
                {carriers.length} carriers
              </summary>
              <div className="mt-3 max-h-60 space-y-3 overflow-auto border-l border-edge-strong pl-3">
                {carriers.map((carrier, index) => (
                  <div key={`${carrier.event_id}-${index}`}>
                    <p className="mono-value">{String(carrier.value)}</p>
                    <p className="mt-1 break-all font-mono text-caption text-ink-faint">
                      {carrier.source_index || 'Source unavailable'}#
                      {carrier.source_id || carrier.event_id}
                    </p>
                    <p className="mt-1 text-caption text-ink-faint">
                      {carrier.timestamp}
                    </p>
                  </div>
                ))}
              </div>
            </details>
          </>
        ) : (
          <span className="text-caption text-ink-faint">
            No carrier captured
          </span>
        )}
      </td>
      <td className="numeric font-mono text-caption text-ink-muted">
        {fact.weight.toFixed(3)}
      </td>
      <td className="numeric font-mono text-caption text-ink-muted">
        {fact.quality.toFixed(2)}
      </td>
      <td className="numeric font-mono text-caption text-ink-muted">
        {fact.confidence.toFixed(2)}
      </td>
      <td className="numeric font-mono text-caption">
        {fact.contribution.toFixed(3)}
      </td>
      <td className="numeric text-ink-muted">{carriers.length}</td>
    </tr>
  )
}

export default function EvidenceFacts({ facts }) {
  if (!facts.length) return <EmptyState title="No evidence facts to show" />
  return (
    <div className="table-scroll max-h-[720px]">
      <table className="data-table min-w-[1000px]" aria-label="Evidence facts">
        <colgroup>
          {[18, 9, 35, 7, 6, 6, 12, 7].map((width, i) => (
            <col key={i} style={{ width: `${width}%` }} />
          ))}
        </colgroup>
        <thead>
          <tr>
            <th>Field / presence</th>
            <th>Role</th>
            <th>Values / source references</th>
            <th className="numeric">
              <abbr title="AHP weight" className="no-underline">
                W
              </abbr>
            </th>
            <th className="numeric">
              <abbr title="Evidence quality" className="no-underline">
                Q
              </abbr>
            </th>
            <th className="numeric">
              <abbr title="Evidence confidence" className="no-underline">
                E
              </abbr>
            </th>
            <th className="numeric">Contribution</th>
            <th className="numeric">Carriers</th>
          </tr>
        </thead>
        <tbody>
          {facts.map((fact) => (
            <FactRow key={fact.field} fact={fact} />
          ))}
        </tbody>
      </table>
    </div>
  )
}
