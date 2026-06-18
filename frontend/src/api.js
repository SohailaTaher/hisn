// API client — wraps fetch calls to the HISN backend.

import { getToken, clearToken } from './auth'

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

async function request(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  }

  // Attach JWT if we have one
  const token = getToken()
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const response = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
  })

  // Auto-logout on 401 — token expired or invalid
  if (response.status === 401) {
    clearToken()
    // We'll let the caller handle the redirect
  }

  if (!response.ok) {
    // Try to extract FastAPI error detail
    let detail
    try {
      const body = await response.json()
      detail = body.detail
    } catch {
      detail = response.statusText
    }
    throw new Error(typeof detail === 'string' ? detail : `API ${response.status}`)
  }

  return response.json()
}

// --- Scans endpoints ---

export function listScans({ limit = 50, offset = 0 } = {}) {
  return request(`/scans?limit=${limit}&offset=${offset}`)
}

export function getScan(scanId) {
  return request(`/scans/${scanId}`)
}

export function createScan({ domain, name }) {
  return request('/scans', {
    method: 'POST',
    body: JSON.stringify({ domain, name }),
  })
}

export async function downloadPdfReport(scanId) {
  const token = getToken()
  if (!token) throw new Error('Not authenticated')

  const response = await fetch(`${BASE_URL}/scans/${scanId}/report.pdf`, {
    headers: { 'Authorization': `Bearer ${token}` },
  })

  if (!response.ok) {
    if (response.status === 401) {
      clearToken()
      throw new Error('Session expired — please log in again')
    }
    throw new Error(`Failed to download report (${response.status})`)
  }

  // Convert response to a blob, create a temp URL, click a hidden link
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `hisn-report-${scanId}.pdf`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  // Free the blob URL once the download has kicked off
  setTimeout(() => URL.revokeObjectURL(url), 100)
}

// --- Auth endpoints ---

export function signup({ email, password, full_name }) {
  return request('/auth/signup', {
    method: 'POST',
    body: JSON.stringify({ email, password, full_name }),
  })
}

export async function login({ email, password }) {
  // /auth/login uses OAuth2PasswordRequestForm which expects form-encoded data,
  // NOT JSON. Special case — we bypass the normal JSON `request()` helper.
  const formData = new URLSearchParams()
  formData.append('username', email)
  formData.append('password', password)

  const response = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: formData,
  })

  if (!response.ok) {
    let detail
    try {
      detail = (await response.json()).detail
    } catch {
      detail = response.statusText
    }
    throw new Error(typeof detail === 'string' ? detail : `Login failed`)
  }

  return response.json()  // { access_token, token_type }
}

export function getMe() {
  return request('/auth/me')
}