import { useEffect, useState, useRef } from 'react'
import { Link, useParams } from 'react-router-dom'
import { AssistantAPI } from '../api/client.js'
import { Card, Spinner, Badge, Empty } from '../components/ui.jsx'
import { useAuth } from '../store/auth.jsx'

export default function Assistant() {
  const { caseId } = useParams()
  const { user } = useAuth()
  const [messages, setMessages] = useState(null)
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const bottomRef = useRef(null)

  useEffect(() => {
    AssistantAPI.history(caseId).then((r) => setMessages(r.data.messages || []))
  }, [caseId])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, busy])

  const send = async (e) => {
    e.preventDefault()
    if (!input.trim() || busy) return
    const q = input
    setInput('')
    setMessages((m) => [...(m || []), { role: 'user', content: q }])
    setBusy(true)
    try {
      const r = await AssistantAPI.ask(caseId, q)
      setMessages((m) => [...(m || []), { role: 'assistant', content: r.data.content, is_hypothesis: r.data.is_hypothesis, intent: r.data.intent }])
    } catch (err) {
      setMessages((m) => [...(m || []), { role: 'assistant', content: 'Error: ' + (err?.response?.data?.detail || 'request failed') }])
    } finally { setBusy(false) }
  }

  return (
    <div className="page">
      <Link to={`/cases/${caseId}`} className="back-link">← Case</Link>
      <h2 className="page-title">AI Investigation Assistant</h2>
      <p className="muted">
        Ask to <strong>summarize</strong>, <strong>explain</strong>, <strong>relate</strong>, <strong>suggest</strong>, or <strong>report</strong>.
        AI output is hypothesis only and requires analyst verification.
      </p>

      <Card className="chat-card">
        <div className="chat-scroll">
          {!messages ? <Spinner /> : messages.length === 0 ? (
            <Empty message="Ask the assistant something about this case." />
          ) : (
            messages.map((m, i) => (
              <div key={i} className={`chat-msg ${m.role}`}>
                <div className="chat-bubble">
                  {m.role === 'assistant' && m.is_hypothesis && <Badge tone="warn">hypothesis</Badge>}
                  <div className="markdown">{m.content}</div>
                </div>
              </div>
            ))
          )}
          {busy && <div className="chat-msg assistant"><div className="chat-bubble">…thinking</div></div>}
          <div ref={bottomRef} />
        </div>
        <form className="form form-inline" onSubmit={send}>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="e.g. Summarize what happened in this case"
            disabled={busy}
          />
          <button className="btn primary" disabled={busy}>Ask</button>
        </form>
      </Card>
    </div>
  )
}