import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { useAuth } from './store/auth.jsx'
import Layout from './components/Layout.jsx'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Cases from './pages/Cases.jsx'
import CaseDetail from './pages/CaseDetail.jsx'
import Timeline from './pages/Timeline.jsx'
import Assistant from './pages/Assistant.jsx'
import Reports from './pages/Reports.jsx'

function ProtectedRoute({ children }) {
  const { isAuthed } = useAuth()
  if (!isAuthed) return <Navigate to="/login" replace />
  return children
}

export default function App() {
  const { isAuthed } = useAuth()
  const location = useLocation()
  if (location.pathname !== '/login' && !isAuthed) {
    return <Navigate to="/login" replace />
  }
  return (
    <Routes>
      <Route path="/login" element={isAuthed ? <Navigate to="/" replace /> : <Login />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="cases" element={<Cases />} />
        <Route path="cases/:caseId" element={<CaseDetail />} />
        <Route path="timeline/:caseId" element={<Timeline />} />
        <Route path="assistant/:caseId" element={<Assistant />} />
        <Route path="reports" element={<Reports />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}