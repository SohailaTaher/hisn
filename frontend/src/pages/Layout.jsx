import { useState, useEffect } from 'react'
import { Link, Outlet, useNavigate } from 'react-router-dom'
import { getMe } from '../api'
import { clearToken } from '../auth'

function Layout() {
  const navigate = useNavigate()
  const [user, setUser] = useState(null)

  useEffect(() => {
    getMe()
      .then(setUser)
      .catch(() => {
        // Token expired/invalid — kick to login
        clearToken()
        navigate('/login', { replace: true })
      })
  }, [navigate])

  function handleLogout() {
    clearToken()
    navigate('/login', { replace: true })
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white border-b border-gray-200 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-8 py-4 flex items-center justify-between">
          <Link to="/" className="inline-flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-blue-800 rounded-lg flex items-center justify-center text-white font-bold text-lg shadow-sm">
              H
            </div>
            <div>
              <div className="text-lg font-bold text-gray-900 leading-tight">
                HISN <span className="text-gray-400 font-normal text-base">حصن</span>
              </div>
              <div className="text-xs text-gray-500 leading-tight">
                External Attack Surface Management
              </div>
            </div>
          </Link>

          <div className="flex items-center gap-4">
            <Link
              to="/scans/new"
              className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded-md transition-colors"
            >
              + New Scan
            </Link>

            {user && (
              <div className="flex items-center gap-3 border-l border-gray-200 pl-4">
                <div className="text-right">
                  <div className="text-sm font-medium text-gray-900 leading-tight">
                    {user.full_name || user.email}
                  </div>
                  {user.full_name && (
                    <div className="text-xs text-gray-500 leading-tight">{user.email}</div>
                  )}
                </div>
                <button
                  onClick={handleLogout}
                  className="text-sm text-gray-600 hover:text-gray-900 font-medium px-3 py-1 border border-gray-300 rounded-md hover:bg-gray-50 transition-colors"
                >
                  Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </header>
      <main className="max-w-7xl mx-auto px-8 py-8">
        <Outlet />
      </main>
    </div>
  )
}

export default Layout