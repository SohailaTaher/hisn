import { useState } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import { login } from '../api'
import { setToken } from '../auth'

function Login() {
  const navigate = useNavigate()
  const location = useLocation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  // After login, send the user back to where they were trying to go, or /
  const from = location.state?.from || '/'

  async function handleSubmit(e) {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      const { access_token } = await login({ email, password })
      setToken(access_token)
      navigate(from, { replace: true })
    } catch (err) {
      setError(err.message)
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="max-w-md w-full">
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-3 mb-4">
            <div className="w-12 h-12 bg-gradient-to-br from-blue-600 to-blue-800 rounded-lg flex items-center justify-center text-white font-bold text-xl shadow-sm">
              H
            </div>
            <div className="text-2xl font-bold text-gray-900">
              HISN <span className="text-gray-400 font-normal">حصن</span>
            </div>
          </div>
          <h1 className="text-xl font-semibold text-gray-900">Sign in to your account</h1>
        </div>

        <form onSubmit={handleSubmit} className="bg-white rounded-lg shadow-sm border border-gray-100 p-6 space-y-4">
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              autoFocus
              autoComplete="email"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              autoComplete="current-password"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting || !email || !password}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-medium py-2 rounded-md transition-colors"
          >
            {submitting ? 'Signing in...' : 'Sign in'}
          </button>
        </form>

        <p className="text-center text-sm text-gray-600 mt-4">
          Don't have an account?{' '}
          <Link to="/signup" className="text-blue-600 hover:underline font-medium">Sign up</Link>
        </p>
      </div>
    </div>
  )
}

export default Login