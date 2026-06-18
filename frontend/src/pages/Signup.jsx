import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { signup, login } from '../api'
import { setToken } from '../auth'

function Signup() {
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [fullName, setFullName] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  async function handleSubmit(e) {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      // 1. Create the account
      await signup({ email, password, full_name: fullName || undefined })
      // 2. Auto-login so user lands straight on dashboard
      const { access_token } = await login({ email, password })
      setToken(access_token)
      navigate('/', { replace: true })
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
          <h1 className="text-xl font-semibold text-gray-900">Create your account</h1>
        </div>

        <form onSubmit={handleSubmit} className="bg-white rounded-lg shadow-sm border border-gray-100 p-6 space-y-4">
          <div>
            <label htmlFor="fullName" className="block text-sm font-medium text-gray-700 mb-1">
              Full name <span className="text-gray-400 font-normal">(optional)</span>
            </label>
            <input
              id="fullName"
              type="text"
              value={fullName}
              onChange={e => setFullName(e.target.value)}
              autoComplete="name"
              autoFocus
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
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
              minLength={8}
              autoComplete="new-password"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <p className="text-xs text-gray-500 mt-1">At least 8 characters.</p>
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting || !email || password.length < 8}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-medium py-2 rounded-md transition-colors"
          >
            {submitting ? 'Creating account...' : 'Create account'}
          </button>
        </form>

        <p className="text-center text-sm text-gray-600 mt-4">
          Already have an account?{' '}
          <Link to="/login" className="text-blue-600 hover:underline font-medium">Sign in</Link>
        </p>
      </div>
    </div>
  )
}

export default Signup