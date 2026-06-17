import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getScan, getPdfReportUrl } from '../api'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

const SEVERITY_STYLES = {
  critical: 'bg-red-100 text-red-800',
  high:     'bg-orange-100 text-orange-800',
  medium:   'bg-yellow-100 text-yellow-800',
  low:      'bg-blue-100 text-blue-800',
  info:     'bg-gray-100 text-gray-800',
  unknown:  'bg-gray-100 text-gray-800',
}

const GRADE_COLOR = {
  A: 'text-green-600',
  B: 'text-green-500',
  C: 'text-yellow-500',
  D: 'text-orange-500',
  F: 'text-red-600',
}

const STATUS_COLOR = {
  done:    'bg-green-100 text-green-800',
  failed:  'bg-red-100 text-red-800',
  running: 'bg-blue-100 text-blue-800',
  pending: 'bg-gray-100 text-gray-800',
}

// Statuses where the scan is still in progress (worth polling)
const ACTIVE_STATUSES = ['pending', 'running']

function ScanDetail() {
  const { scanId } = useParams()
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    let intervalId = null

    async function fetchScan() {
      try {
        const data = await getScan(scanId)
        if (cancelled) return
        setScan(data)
        setLoading(false)
        setError(null)

        // Stop polling once the scan finishes
        if (!ACTIVE_STATUSES.includes(data.status) && intervalId) {
          clearInterval(intervalId)
          intervalId = null
        }
      } catch (err) {
        if (cancelled) return
        setError(err.message)
        setLoading(false)
      }
    }

    // Initial fetch
    fetchScan()

    // Set up polling every 3 seconds — will auto-stop when status hits done/failed
    intervalId = setInterval(fetchScan, 3000)

    // Cleanup: runs when user navigates away OR scanId changes
    return () => {
      cancelled = true
      if (intervalId) clearInterval(intervalId)
    }
  }, [scanId])

  if (loading) {
    return <div className="p-8 text-gray-600">Loading scan details...</div>
  }
  if (error && !scan) {
    return (
      <div className="min-h-screen bg-gray-50 p-8">
        <Link to="/" className="text-blue-600 hover:underline mb-4 inline-block">← Back to scans</Link>
        <div className="text-red-600">Error: {error}</div>
      </div>
    )
  }

  const isActive = ACTIVE_STATUSES.includes(scan.status)

  // Group findings by severity
  const findingsBySeverity = {}
  for (const f of scan.findings) {
    if (!findingsBySeverity[f.severity]) findingsBySeverity[f.severity] = []
    findingsBySeverity[f.severity].push(f)
  }

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="flex items-center justify-between mb-4">
        <Link to="/" className="text-blue-600 hover:underline">
          ← Back to scans
        </Link>
        <a
          href={getPdfReportUrl(scanId)}
          target="_blank"
          rel="noopener noreferrer"
          className="bg-blue-600 hover:bg-blue-700 text-white font-medium px-4 py-2 rounded-md transition-colors text-sm"
        >
          ↓ Download PDF
        </a>
      </div>

      {/* Header card */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <div className="flex items-start justify-between mb-4">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">{scan.target.domain}</h1>
            <p className="text-sm text-gray-500 mt-1">
              Scan #{scan.id}{scan.target.name ? ` · ${scan.target.name}` : ''}
            </p>
          </div>
          <div className="flex flex-col items-end gap-1">
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${STATUS_COLOR[scan.status] || 'bg-gray-100 text-gray-800'}`}>
              {scan.status}
            </span>
            {isActive && (
              <span className="text-xs text-blue-600 flex items-center gap-1">
                <span className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></span>
                Auto-refreshing
              </span>
            )}
          </div>
        </div>

        <div className="grid grid-cols-3 gap-6 pt-4 border-t border-gray-100">
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">Score</div>
            <div className="text-3xl font-bold text-gray-900">{scan.overall_score ?? '—'}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">Grade</div>
            <div className={`text-3xl font-bold ${GRADE_COLOR[scan.overall_grade] || 'text-gray-400'}`}>
              {scan.overall_grade ?? '—'}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">Findings</div>
            <div className="text-3xl font-bold text-gray-900">{scan.findings.length}</div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-6 mt-4 pt-4 border-t border-gray-100 text-sm">
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">Started</div>
            <div className="text-gray-700">{new Date(scan.started_at).toLocaleString()}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">Finished</div>
            <div className="text-gray-700">
              {scan.finished_at ? new Date(scan.finished_at).toLocaleString() : '—'}
            </div>
          </div>
        </div>
      </div>

      {/* Findings */}
      {scan.findings.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-6 text-gray-600">
          {isActive ? 'Scan in progress — findings will appear here as they\'re discovered.' : 'No findings recorded for this scan.'}
        </div>
      ) : (
        <div className="space-y-4">
          {SEVERITY_ORDER.map(sev => {
            const items = findingsBySeverity[sev]
            if (!items || items.length === 0) return null
            return (
              <div key={sev} className="bg-white rounded-lg shadow overflow-hidden">
                <div className="px-6 py-3 border-b border-gray-100 flex items-center gap-3">
                  <span className={`px-2 py-1 rounded text-xs font-medium uppercase ${SEVERITY_STYLES[sev]}`}>
                    {sev}
                  </span>
                  <span className="text-sm text-gray-700">
                    {items.length} finding{items.length !== 1 ? 's' : ''}
                  </span>
                </div>
                <div className="divide-y divide-gray-100">
                  {items.map(f => (
                    <div key={f.id} className="px-6 py-4">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <div className="text-sm font-medium text-gray-900">{f.title}</div>
                          {f.description && (
                            <div className="text-sm text-gray-600 mt-1">{f.description}</div>
                          )}
                        </div>
                        <span className="text-xs text-gray-500 font-mono whitespace-nowrap">
                          {f.scanner_name}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default ScanDetail