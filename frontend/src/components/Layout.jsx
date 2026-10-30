import { useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../store/auth.jsx'

const NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/cases', label: 'Investigations' },
  { to: '/reports', label: 'Reports' },
]

export default function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="layout">
      <aside className={`sidebar ${open ? 'open' : ''}`}>
        <div className="brand">
          <span className="brand-badge">DT</span>
          <div>
            <h1>DeepTrace</h1>
            <p>Digital Forensics</p>
          </div>
        </div>
        <nav>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} onClick={() => setOpen(false)}
                     className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="user-chip">
            <div>
              <strong>{user?.username}</strong>
              <span className="role">{user?.role}</span>
            </div>
            <button className="btn-ghost" onClick={handleLogout}>Sign out</button>
          </div>
        </div>
      </aside>
      {open && <div className="backdrop" onClick={() => setOpen(false)} />}
      <div className="main">
        <header className="topbar">
          <button className="btn-ghost menu-btn" onClick={() => setOpen(true)}>☰</button>
          <span className="topbar-title">Investigation Workspace</span>
          <span className="status-pill">Evidence integrity: enforced</span>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}