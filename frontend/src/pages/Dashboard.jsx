import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { DashboardAPI } from '../api/client.js'
import { Card, Stat, Spinner, Empty, Badge, integrityTone } from '../components/ui.jsx'

export default function Dashboard() {
  const [overview, setOverview] = useState(null)
  const [activity, setActivity] = useState([])
  const [buckets, setBuckets] = useState([])
  const [error, setError] = useState('')

  useEffect(() => {
    Promise.all([DashboardAPI.overview(), DashboardAPI.activity(), DashboardAPI.timelineBucket()])
      .then(([o, a, t]) => {
        setOverview(o.data)
        setActivity(a.data.activity || [])
        setBuckets(t.data.buckets || [])
      })
      .catch((e) => setError(e?.response?.data?.detail || 'Could not load dashboard'))
  }, [])

  if (error) return <div className="alert error">{error}</div>
  if (!overview) return <Spinner />

  const sev = overview.findings_by_severity || {}
  const severityChart = Object.entries(sev).map(([k, v]) => ({ name: k, count: v }))

  return (
    <div className="page">
      <h2 className="page-title">Investigation Overview</h2>
      <div className="stat-grid">
        <Stat label="Investigations" value={overview.cases} />
        <Stat label="Evidence items" value={overview.evidence_total} />
        <Stat label="Integrity verified" value={overview.evidence_verified} tone="success" />
        <Stat label="Integrity failed" value={overview.evidence_failed} tone={overview.evidence_failed ? 'danger' : ''} />
        <Stat label="Findings" value={overview.findings_total} />
        <Stat label="Timeline events" value={overview.events_total} />
        <Stat label="Analysis runs" value={overview.analysis_runs_completed} />
      </div>

      <div className="grid-2">
        <Card title="Findings by Severity">
          {severityChart.length ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={severityChart}>
                <XAxis dataKey="name" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#6c5ce7" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <Empty message="No findings yet." />
          )}
        </Card>
        <Card title="Evidence by Type">
          {Object.keys(overview.evidence_by_type || {}).length ? (
            <ul className="kv-list">
              {Object.entries(overview.evidence_by_type).map(([k, v]) => (
                <li key={k}><Badge tone="neutral">{k}</Badge><span>{v}</span></li>
              ))}
            </ul>
          ) : (
            <Empty message="No evidence uploaded." />
          )}
        </Card>
      </div>

      <Card title="Event Volume Over Time">
        {buckets.length ? (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={buckets}>
              <XAxis dataKey="time" minTickGap={40} />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="count" fill="#00b894" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <Empty message="Nothing to visualize yet — run analysis modules to populate the timeline." />
        )}
      </Card>

      <Card title="Investigation Activity Log">
        {activity.length ? (
          <table className="table">
            <thead>
              <tr><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Target</th></tr>
            </thead>
            <tbody>
              {activity.slice(0, 15).map((a) => (
                <tr key={a.id}>
                  <td className="mono">{a.timestamp}</td>
                  <td>{a.actor}</td>
                  <td><Badge tone="neutral">{a.action}</Badge></td>
                  <td>{a.target_type} #{a.target_id ?? '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty message="No activity recorded." />
        )}
      </Card>
    </div>
  )
}