import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { createScan } from '../api'

function NewScan() {
  const navigate = useNavigate()

  // Controlled inputs: state stores what's in the input
  const [domain, setDomain] = useState('')
  const [name, setName] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  async function handleSubmit(e) {
    e.preventDefault()   // 👈 stops the browser from reloading on form submit
    setError(null)
    setSubmitting(true)

    try {
      const scan = await createScan({
        domain: domain.trim(),
        name: name.trim() || undefined,
      })
      // Success — go straight to the detail page for this new scan
      navigate(`/scans/${scan.id}`)
    } catch (err) {
      setError(err.message)
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <Link to="/" className="text-blue-600 hover:underline mb-4 inline-block">
        ← Back to scans
      </Link>

      <div className="max-w-xl">
        <h1 className="text-3xl font-bold text-gray-900 mb-6">New Scan</h1>

        <form onSubmit={handleSubmit} className="bg-white rounded-lg shadow p-6 space-y-4">
          {/* Domain field */}
          <div>
            <label htmlFor="domain" className="block text-sm font-medium text-gray-700 mb-1">
              Domain <span className="text-red-500">*</span>
            </label>
            <input
              id="domain"
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              required
              autoFocus
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <p className="text-xs text-gray-500 mt-1">
              Just the domain, no protocol. e.g. <code className="bg-gray-100 px-1">github.com</code> (not https://github.com)
            </p>
          </div>

          {/* Optional name field */}
          <div>
            <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-1">
              Display name <span className="text-gray-400 font-normal">(optional)</span>
            </label>
            <input
              id="name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="GitHub"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <p className="text-xs text-gray-500 mt-1">
              Friendly name shown in the dashboard. Defaults to the domain.
            </p>
          </div>

          {/* Error message */}
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm">
              {error}
            </div>
          )}

          {/* Submit / Cancel buttons */}
          <div className="flex items-center gap-3 pt-2">
            <button
              type="submit"
              disabled={submitting || !domain.trim()}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-medium px-4 py-2 rounded-md transition-colors"
            >
              {submitting ? 'Starting scan...' : 'Start scan'}
            </button>
            <Link to="/" className="text-gray-600 hover:text-gray-900 font-medium px-4 py-2">
              Cancel
            </Link>
          </div>
        </form>
      </div>
    </div>
  )
}

export default NewScan