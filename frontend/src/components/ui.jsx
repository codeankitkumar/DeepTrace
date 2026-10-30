export function Card({ title, children, className = '' }) {
  return (
    <div className={`card ${className}`}>
      {title && <h3 className="card-title">{title}</h3>}
      {children}
    </div>
  )
}

export function Stat({ label, value, tone = '' }) {
  return (
    <div className={`stat ${tone}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

export function Badge({ children, tone = 'neutral' }) {
  return <span className={`badge badge-${tone}`}>{children}</span>
}

export function Spinner() {
  return <div className="spinner" aria-label="loading" />
}

export function Empty({ message = 'No data yet.' }) {
  return <div className="empty">{message}</div>
}

export function severityTone(sev) {
  const map = {
    critical: 'danger',
    high: 'danger',
    medium: 'warn',
    low: 'info',
    info: 'neutral',
  }
  return map[sev] || 'neutral'
}

export function integrityTone(status) {
  return { verified: 'success', failed: 'danger', pending: 'neutral' }[status] || 'neutral'
}