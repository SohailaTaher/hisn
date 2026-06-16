import { useState, useEffect } from 'react'
import { listScans } from './api'

function App() {
  // 1. STATE: three pieces of state — the data, whether we're loading, any error
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // 2. EFFECT: runs once when the component mounts (the [] at the end means "run once")
  useEffect(() => {
    listScans()
      .then(data => {
        setScans(data.scans)
        setLoading(false)
      })
      .catch(err => {
        setError(err.message)
        setLoading(false)
      })
  }, [])

  // 3. CONDITIONAL RENDERING: different UI based on state
  if (loading) {
    return <div className="p-8 text-gray-600">Loading scans...</div>
  }
  if (error) {
    return <div className="p-8 text-red-600">Error: {error}</div>
  }

  // 4. LIST RENDERING: map() turns an array of data into an array of JSX rows
  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <h1 className="text-3xl font-bold text-gray-900 mb-6">HISN — Scans</h1>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Target</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Score</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Grade</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Started</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {scans.map(scan => (
              <tr key={scan.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 text-sm text-gray-900">{scan.id}</td>
                <td className="px-6 py-4 text-sm text-gray-900">Target #{scan.target_id}</td>
                <td className="px-6 py-4 text-sm text-gray-900">{scan.status}</td>
                <td className="px-6 py-4 text-sm text-gray-900">{scan.overall_score ?? '—'}</td>
                <td className="px-6 py-4 text-sm font-medium text-gray-900">{scan.overall_grade ?? '—'}</td>
                <td className="px-6 py-4 text-sm text-gray-500">
                  {new Date(scan.started_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default App