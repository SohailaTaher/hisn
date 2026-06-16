// API client — wraps fetch calls to the HISN backend.
// One file = one source of truth for the base URL + error handling.

const BASE_URL = 'http://localhost:8000'

async function request(path, options = {}) {
  const response = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!response.ok) {
    throw new Error(`API ${response.status}: ${response.statusText}`)
  }
  return response.json()
}

// Public functions — one per endpoint we built last week
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