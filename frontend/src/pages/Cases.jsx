import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { CaseAPI } from '../api/client.js'
import { Card, Spinner, Badge, Empty } from '../components/ui.jsx'
import { useAuth } from '../store/auth.jsx'

export default function Cases() {
  const { canAnalyze } = useAuth()
  const [cases, setCases] = useState(null)
  const [error, setError] = useState('')
  const [showNew, setShowNew] = useState(false)
  const [form, setForm] = useState({ name: '', description: '', reference_number: '' })

  const load = () =>
    CaseAPI.list().then((r) => setCases(r.data)).catch((e) => setError(e?.response?.data?.detail || 'Failed'))

  useEffect(() => { load() }, [])

  const create = async (e) => {
    e.preventDefault()
    await CaseAPI.create(form)
    setShowNew(false)
    setForm({ name: '', description: '', reference_number: '' })
    load()
  }

  const statusTone = { open: 'success', closed: 'neutral', archived: 'neutral' }

  return (
    <div className="page">
      <div className="page-head">
        <h2 className="page-title">Investigations</h2>
        {canAnalyze && (
          <button className="btn primary" onClick={() => setShowNew(!showNew)}>
            {showNew ? 'Cancel' : '+ New case'}
          </button>
        )}
      </div>

      {error && <div className="alert error">{error}</div>}
      {showNew && (
        <Card title="Create investigation">
          <form className="form" onSubmit={create}>
            <label>Name *<input value={form.name} required onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
            <label>Reference number
              <input value={form.reference_number} onChange={(e) => setForm({ ...form, reference_number: e.target.value })} />
            </label>
            <label>Description
              <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </label>
            <button className="btn primary" type="submit">Create</button>
          </form>
        </Card>
      )}

      {!cases ? (
        <Spinner />
      ) : cases.length === 0 ? (
        <Empty message="No investigations. Create one to begin ingesting evidence." />
      ) : (
        <div className="case-grid">
          {cases.map((c) => (
            <Link key={c.id} to={`/cases/${c.id}`} className="case-card">
              <div className="case-card-head">
                <h3>{c.name}</h3>
                <Badge tone={statusTone[c.status] || 'neutral'}>{c.status}</Badge>
              </div>
              <p>{c.description || 'No description.'}</p>
              <div className="case-meta">
                <span>Ref: {c.reference_number || 'N/A'}</span>
                <span>Case #{c.id}</span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}