import { createContext, useContext, useMemo, useState } from 'react'
import { AuthAPI } from '../api/client'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('deeptrace_user')) || null
    } catch {
      return null
    }
  })

  const login = async (username, password) => {
    const { data } = await AuthAPI.login(username, password)
    localStorage.setItem('deeptrace_access', data.access_token)
    localStorage.setItem('deeptrace_user', JSON.stringify(data.user))
    setUser(data.user)
    return data.user
  }

  const logout = () => {
    localStorage.removeItem('deeptrace_access')
    localStorage.removeItem('deeptrace_user')
    setUser(null)
  }

  const value = useMemo(
    () => ({
      user,
      login,
      logout,
      isAuthed: Boolean(user),
      isAdmin: user?.role === 'admin',
      canAnalyze: user?.role === 'admin' || user?.role === 'analyst',
    }),
    [user]
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}