import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { listScans } from '../api'

function ScansList() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

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

  if (loading) return <div className="text-gray-600">Loading scans...</div>
  if (error) return <div className="text-red-600">Error: {error}</div>

  // Compute dashboard stats from the scans we have
  const totalScans = scans.length
  const completedScans = scans.filter(s => s.status === 'done').length
  const activeScans = scans.filter(s => s.status === 'pending' || s.status === 'running').length
  const scoredScans = scans.filter(s => s.status === 'done' && s.overall_score != null)
  const avgScore = scoredScans.length > 0
    ? Math.round(scoredScans.reduce((sum, s) => sum + s.overall_score, 0) / scoredScans.length)
    : null

  return (
    <>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-sm text-gray-500 mt-1">Overview of all scans and security posture</p>
      </div>

      {/* Stats cards row */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="bg-white rounded-lg shadow-sm border border-gray-100 p-5">
          <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Total Scans</div>
          <div className="text-3xl font-bold text-gray-900 mt-2">{totalScans}</div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-100 p-5">
          <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Completed</div>
          <div className="text-3xl font-bold text-green-600 mt-2">{completedScans}</div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-100 p-5">
          <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">In Progress</div>
          <div className="text-3xl font-bold text-blue-600 mt-2">{activeScans}</div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-100 p-5">
          <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Avg Score</div>
          <div className="text-3xl font-bold text-gray-900 mt-2">
            {avgScore ?? '—'}
            {avgScore != null && <span className="text-base font-normal text-gray-400">/100</span>}
          </div>
        </div>
      </div>

      {/* Scans table */}
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-900">Recent Scans</h2>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-gray-100 overflow-hidden">
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
              <tr
                key={scan.id}
                className="hover:bg-blue-50 cursor-pointer transition-colors"
                onClick={() => navigate(`/scans/${scan.id}`)}
              >
                <td className="px-6 py-4 text-sm text-gray-900">#{scan.id}</td>
                <td className="px-6 py-4 text-sm text-gray-900">Target #{scan.target_id}</td>
                <td className="px-6 py-4 text-sm">
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                    scan.status === 'done' ? 'bg-green-100 text-green-800' :
                    scan.status === 'failed' ? 'bg-red-100 text-red-800' :
                    scan.status === 'running' ? 'bg-blue-100 text-blue-800' :
                    'bg-gray-100 text-gray-800'
                  }`}>
                    {scan.status}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-900">{scan.overall_score ?? '—'}</td>
                <td className={`px-6 py-4 text-sm font-bold ${
                  scan.overall_grade === 'A' ? 'text-green-600' :
                  scan.overall_grade === 'B' ? 'text-green-500' :
                  scan.overall_grade === 'C' ? 'text-yellow-500' :
                  scan.overall_grade === 'D' ? 'text-orange-500' :
                  scan.overall_grade === 'F' ? 'text-red-600' :
                  'text-gray-400'
                }`}>
                  {scan.overall_grade ?? '—'}
                </td>
                <td className="px-6 py-4 text-sm text-gray-500">
                  {new Date(scan.started_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

export default ScansList