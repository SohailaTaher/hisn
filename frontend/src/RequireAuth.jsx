import { Navigate, useLocation } from 'react-router-dom'
import { isLoggedIn } from './auth'

function RequireAuth({ children }) {
  const location = useLocation()

  if (!isLoggedIn()) {
    // Save where the user was trying to go, so we can send them back after login
    return <Navigate to="/login" state={{ from: location.pathname }} replace />
  }
  return children
}

export default RequireAuth