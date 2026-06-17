import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { listScans } from '../api'

function ScansList() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const navigate = useNavigate()   // 👈 React Router gives us this hook

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

  if (loading) return <div className="p-8 text-gray-600">Loading scans...</div>
  if (error) return <div className="p-8 text-red-600">Error: {error}</div>

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="flex items-center justify-between mb-6">
  <h1 className="text-3xl font-bold text-gray-900">HISN — Scans</h1>
  <Link
    to="/scans/new"
    className="bg-blue-600 hover:bg-blue-700 text-white font-medium px-4 py-2 rounded-md transition-colors"
  >
    + New Scan
  </Link>
</div>

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
              <tr
                key={scan.id}
                className="hover:bg-blue-50 cursor-pointer"
                onClick={() => navigate(`/scans/${scan.id}`)}
              >
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

export default ScansList