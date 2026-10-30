import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { TimelineAPI } from '../api/client.js'
import { Card, Spinner, Badge, Empty, severityTone } from '../components/ui.jsx'

export default function Timeline() {
  const { caseId } = useParams()
  const [data, setData] = useState(null)
  const [anomalies, setAnomalies] = useState([])
  const [summary, setSummary] = useState(null)

  useEffect(() => {
    Promise.all([TimelineAPI.events(caseId), TimelineAPI.anomalies(caseId), TimelineAPI.summary(caseId)])
      .then(([e, a, s]) => { setData(e.data.events || []); setAnomalies(a.data.anomalies || []); setSummary(s.data) })
      .catch(() => setData([]))
  }, [caseId])

  return (
    <div className="page">
      <Link to={`/cases/${caseId}`} className="back-link">← Case</Link>
      <h2 className="page-title">Timeline Reconstruction</h2>

      <div className="stat-grid compact">
        <div className="stat"><div className="stat-value">{summary?.total_events ?? data?.length ?? 0}</div><div className="stat-label">Events</div></div>
        <div className="stat"><div className="stat-value">{anomalies.length}</div><div className="stat-label">Unusual sequences</div></div>
        <div className="stat"><div className="stat-value">{summary?.earliest_utc?.slice(0, 16) || '—'}</div><div className="stat-label">Earliest (UTC)</div></div>
        <div className="stat"><div className="stat-value">{summary?.latest_utc?.slice(0, 16) || '—'}</div><div className="stat-label">Latest (UTC)</div></div>
      </div>

      {anomalies.length > 0 && (
        <Card title="Unusual sequences (hypotheses)">
          {anomalies.map((a, i) => (
            <div className="finding" key={i}>
              <div className="finding-head">
                <Badge tone={severityTone(a.severity)}>{a.severity}</Badge>
                <strong>{a.type}</strong>
                <Badge tone="warn">hypothesis</Badge>
              </div>
              <p>{a.description} <span className="muted">— confidence {a.confidence}</span></p>
            </div>
          ))}
        </Card>
      )}

      <Card title="Chronological events">
        {!data ? <Spinner /> : data.length === 0 ? (
          <Empty message="Run analysis modules to populate the timeline." />
        ) : (
          <table className="table">
            <thead><tr><th>Time (UTC)</th><th>Source</th><th>Category</th><th>Event</th></tr></thead>
            <tbody>
              {data.map((e) => (
                <tr key={e.id}>
                  <td className="mono">{e.event_time_utc}</td>
                  <td><Badge tone="neutral">{e.source_module}</Badge></td>
                  <td>{e.category || '-'}</td>
                  <td>{e.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}