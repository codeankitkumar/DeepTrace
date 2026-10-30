import axios from 'axios'

const BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api'

export const api = axios.create({
  baseURL: BASE,
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('deeptrace_access')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response && err.response.status === 401) {
      localStorage.removeItem('deeptrace_access')
      localStorage.removeItem('deeptrace_user')
      // avoid redirect loop on login endpoint
      if (!window.location.pathname.startsWith('/login')) {
        window.location.href = '/login'
      }
    }
    return Promise.reject(err)
  }
)

export const AuthAPI = {
  login: (username, password) => api.post('/auth/login', { username, password }),
  me: () => api.get('/auth/me'),
}

export const CaseAPI = {
  list: () => api.get('/cases'),
  create: (data) => api.post('/cases', data),
  get: (id) => api.get(`/cases/${id}`),
  update: (id, data) => api.patch(`/cases/${id}`, data),
}

export const EvidenceAPI = {
  list: (caseId) => api.get('/evidence', { params: { case_id: caseId } }),
  upload: (caseId, formData) =>
    api.post('/evidence', formData, {
      params: { case_id: caseId },
      headers: { 'Content-Type': 'multipart/form-data' },
    }),
  verify: (id) => api.post(`/evidence/${id}/verify`),
  custody: (id) => api.get(`/evidence/${id}/custody`),
  run: (id, moduleName) => api.post(`/evidence/${id}/run/${moduleName}`),
  findings: (id) => api.get(`/evidence/${id}/findings`),
}

export const TimelineAPI = {
  events: (caseId) => api.get(`/timeline/${caseId}/events`),
  anomalies: (caseId) => api.get(`/timeline/${caseId}/anomalies`),
  summary: (caseId) => api.get(`/timeline/${caseId}/summary`),
}

export const ModulesAPI = {
  list: () => api.get('/modules'),
}

export const DashboardAPI = {
  overview: () => api.get('/dashboard/overview'),
  activity: () => api.get('/dashboard/activity'),
  timelineBucket: () => api.get('/dashboard/timeline-bucket'),
}

export const AssistantAPI = {
  ask: (caseId, query) => api.post(`/assistant/${caseId}/ask`, { query }),
  history: (caseId) => api.get(`/assistant/${caseId}/history`),
}

export const ReportsAPI = {
  generate: (caseId) => api.get(`/reports/${caseId}/generate`),
  markdown: (caseId) => api.get(`/reports/${caseId}/markdown`),
}