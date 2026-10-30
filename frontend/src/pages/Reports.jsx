import { useEffect, useState } from 'react'
import { CaseAPI, ReportsAPI } from '../api/client.js'
import { Card, Spinner, Empty, Badge, integrityTone } from '../components/ui.jsx'
import { useAuth } from '../store/auth.jsx'

export default function Reports() {
  const { user } = useAuth()
  const [cases, setCases] = useState(null)
  const [selected, setSelected] = useState('')
  const [report, setReport] = useState(null)
  const [md, setMd] = useState('')

  useEffect(() => { CaseAPI.list().then((r) => setCases(r.data)).catch(() => setCases([])) }, [])

  const showMd = async (id) => {
    const r = await ReportsAPI.markdown(id)
    setMd(r.data)
    setReport(null)
  }

  return (
    <div className="page">
      <h2 className="page-title">Forensic Reports</h2>
      <p className="muted">Generate structured, reproducible reports from verified case data.</p>

      {!cases ? <Spinner /> : cases.length === 0 ? (
        <Empty message="No investigations available for reporting." />
      ) : (
        <div className="grid-2">
          <Card title="Generate a report">
            <label>Investigation
              <select value={selected} onChange={(e) => setSelected(e.target.value)}>
                <option value="">Select…</option>
                {cases.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
            </label>
            <div className="btn-row" style={{ marginTop: 12 }}>
              <button className="btn primary" disabled={!selected}
                onClick={async () => { const r = await ReportsAPI.generate(selected); setReport(r.data); setMd('') }}>
                Generate report
              </button>
              <button className="btn" disabled={!selected} onClick={() => showMd(selected)}>Markdown</button>
            </div>
          </Card>

          {report && (
            <Card title={`Report · ${report.case_information?.name}`}>
              <div className="kv-list">
                <li><span>Generated (UTC)</span><span className="mono small">{report.report_metadata?.generated_at_utc}</span></li>
                <li><span>Analyst</span><span>{report.report_metadata?.analyst}</span></li>
                <li><span>Evidence</span><span>{report.evidence_inventory?.length} items · {report.integrity_summary?.verified} verified</span></li>
                <li><span>Verified findings</span><span>{report.findings_sections?.verified_findings}</span></li>
                <li><span>Hypotheses</span><span>{report.findings_sections?.hypotheses}</span></li>
                <li><span>Timeline events</span><span>{report.timeline?.length}</span></li>
              </div>
              <h4>Evidence inventory</h4>
              <table className="table">
                <thead><tr><th>Name</th><th>SHA-256</th><th>Integrity</th></tr></thead>
                <tbody>
                  {report.evidence_inventory?.map((e) => (
                    <tr key={e.id}>
                      <td>{e.name}</td>
                      <td className="mono small">{e.sha256 ? e.sha256.slice(0, 20) + '…' : '-'}</td>
                      <td><Badge tone={integrityTone(e.integrity_status)}>{e.integrity_status}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <h4>Findings</h4>
              {report.findings?.map((f) => (
                <div className="finding" key={f.id}>
                  <strong>{f.title}</strong> {f.is_hypothesis ? <Badge tone="warn">hypothesis</Badge> : <Badge tone="success">verified</Badge>}
                  <p className="small">{f.description}</p>
                </div>
              ))}
            </Card>
          )}
        </div>
      )}

      {md && (
        <Card title="Markdown report">
          <pre className="md-pre">{md}</pre>
        </Card>
      )}
    </div>
  )
}