import { useState, useEffect } from 'react'
import { Link, useParams } from 'react-router-dom'
import { CaseAPI, EvidenceAPI, ModulesAPI } from '../api/client.js'
import { Card, Spinner, Badge, Empty, integrityTone, severityTone } from '../components/ui.jsx'
import { useAuth } from '../store/auth.jsx'

export default function CaseDetail() {
  const { caseId } = useParams()
  const { canAnalyze } = useAuth()
  const [caseInfo, setCaseInfo] = useState(null)
  const [evidence, setEvidence] = useState(null)
  const [modules, setModules] = useState([])
  const [findings, setFindings] = useState([])
  const [custody, setCustody] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')

  const load = () => {
    setError('')
    Promise.all([CaseAPI.get(caseId), EvidenceAPI.list(caseId), ModulesAPI.list()])
      .then(([c, e, m]) => {
        setCaseInfo(c.data)
        setEvidence(e.data)
        setModules(m.data.modules || [])
      })
      .catch((err) => setError(err?.response?.data?.detail || 'Failed to load case'))
  }

  useEffect(() => { load() }, [caseId])

  const handleUpload = async (e) => {
    e.preventDefault()
    setBusy('upload')
    const file = e.target.file.files[0]
    if (!file) { setBusy(''); return }
    const fd = new FormData()
    fd.append('file', file)
    fd.append('category', e.target.category.value)
    fd.append('description', e.target.description.value)
    fd.append('evidence_type', e.target.evidence_type.value || '')
    try {
      await EvidenceAPI.upload(caseId, fd)
      load()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Upload failed')
    } finally { setBusy('') }
  }

  const verify = async (id) => {
    setBusy(`v${id}`)
    try { await EvidenceAPI.verify(id); load() } finally { setBusy('') }
  }

  const runModule = async (id, moduleName) => {
    setBusy(`r${id}-${moduleName}`)
    try {
      await EvidenceAPI.run(id, moduleName)
      load()
      showFindings(id)
    } finally { setBusy('') }
  }

  const showFindings = async (id) => {
    const r = await EvidenceAPI.findings(id)
    setFindings([...findings.filter((f) => f.evidence_id !== id), ...r.data])
  }

  const showCustody = async (id) => {
    const r = await EvidenceAPI.custody(id)
    setCustody(r.data)
  }

  if (!caseInfo) return <Spinner />

  return (
    <div className="page">
      <Link to="/cases" className="back-link">← Investigations</Link>
      <div className="page-head">
        <h2 className="page-title">{caseInfo.name} <Badge tone="neutral">{caseInfo.status}</Badge></h2>
        <div className="actions">
          <Link className="btn" to={`/timeline/${caseId}`}>Timeline</Link>
          <Link className="btn" to={`/assistant/${caseId}`}>AI Assistant</Link>
        </div>
      </div>
      <p className="muted">{caseInfo.description || 'No description.'} · Ref {caseInfo.reference_number || 'N/A'}</p>
      {error && <div className="alert error">{error}</div>}

      {canAnalyze && (
        <Card title="Upload evidence">
          <form className="form form-inline" onSubmit={handleUpload}>
            <input type="file" name="file" required />
            <select name="category" defaultValue="uncategorized">
              <option value="uncategorized">Uncategorized</option>
              <option>disk image</option><option>memory</option><option>logs</option>
              <option>browser</option><option>network</option><option>document</option>
            </select>
            <select name="evidence_type">
              <option value="">Auto-detect</option>
              <option value="file">File</option><option value="evtx">EVTX</option>
              <option value="browser">Browser</option><option value="memory">Memory</option>
              <option value="network">Network</option>
            </select>
            <input name="description" placeholder="Description (optional)" />
            <button className="btn primary" disabled={busy === 'upload'}>
              {busy === 'upload' ? 'Uploading…' : 'Upload'}
            </button>
          </form>
        </Card>
      )}

      <Card title={`Evidence Inventory (${evidence?.length || 0})`}>
        {!evidence ? <Spinner /> : evidence.length === 0 ? (
          <Empty message="No evidence yet." />
        ) : (
          <table className="table">
            <thead>
              <tr><th>ID</th><th>Name</th><th>Type</th><th>Category</th><th>Integrity</th><th>SHA-256</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {evidence.map((ev) => (
                <tr key={ev.id}>
                  <td>{ev.id}</td>
                  <td>{ev.original_name}</td>
                  <td><Badge tone="neutral">{ev.evidence_type}</Badge></td>
                  <td>{ev.category}</td>
                  <td><Badge tone={integrityTone(ev.integrity_status)}>{ev.integrity_status}</Badge></td>
                  <td className="mono small">{ev.sha256_original ? ev.sha256_original.slice(0, 16) + '…' : '-'}</td>
                  <td className="btn-row">
                    {canAnalyze && (
                      <button className="btn tiny" disabled={busy === `v${ev.id}`} onClick={() => verify(ev.id)}>Verify</button>
                    )}
                    <button className="btn tiny" onClick={() => showCustody(ev.id)}>Custody</button>
                    <button className="btn tiny" onClick={() => showFindings(ev.id)}>Findings</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* __PART2__ */}

      {canAnalyze && modules.length > 0 && (
        <Card title="Run analysis modules">
          <p className="muted">Analysis runs on a decrypted, hash-verified working copy — the original is never modified.</p>
          <div className="module-grid">
            {modules.map((m) => (
              <div className="module-card" key={m.name}>
                <strong>{m.display_name}</strong>
                <p>{m.description}</p>
                <span className="mono small">{m.name}</span>
              </div>
            ))}
          </div>
          <div className="btn-row">
            {modules.map((m) => (
              <button key={m.name} className="btn tiny"
                onClick={() => evidence?.forEach((ev) => runModule(ev.id, m.name))}>
                Run {m.name} on all
              </button>
            ))}
          </div>
        </Card>
      )}

      {custody && (
        <Card title={`Chain of custody (evidence #${custody[0]?.evidence_id ?? '?'})`}>
          <table className="table">
            <thead><tr><th>Action</th><th>Actor</th><th>From</th><th>To</th><th>Time (UTC)</th><th>Checksum</th></tr></thead>
            <tbody>
              {custody.map((c) => (
                <tr key={c.timestamp}>
                  <td><Badge tone="neutral">{c.action}</Badge></td>
                  <td>{c.actor_name}</td><td>{c.from_party || '-'}</td><td>{c.to_party || '-'}</td>
                  <td className="mono small">{c.timestamp}</td><td className="mono small">{c.checksum?.slice(0, 12)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
          <button className="btn tiny" onClick={() => setCustody(null)}>Close</button>
        </Card>
      )}

      {findings.length > 0 && (
        <Card title={`Findings (${findings.length})`}>
          {findings.map((f) => (
            <div className="finding" key={f.id}>
              <div className="finding-head">
                <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
                <strong>{f.title}</strong>
                {f.is_hypothesis && <Badge tone="warn">hypothesis</Badge>}
              </div>
              <p>{f.description}</p>
              <span className="small muted">module: {f.module} · confidence {f.confidence}</span>
            </div>
          ))}
        </Card>
      )}
    </div>
  )
}