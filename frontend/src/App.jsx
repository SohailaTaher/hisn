import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './pages/Layout'
import ScansList from './pages/ScansList'
import ScanDetail from './pages/ScanDetail'
import NewScan from './pages/NewScan'
import Login from './pages/Login'
import Signup from './pages/Signup'
import RequireAuth from './RequireAuth'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public — no auth required */}
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />

        {/* Protected — must be logged in. RequireAuth wraps Layout, Layout wraps pages. */}
        <Route element={<RequireAuth><Layout /></RequireAuth>}>
          <Route path="/" element={<ScansList />} />
          <Route path="/scans/new" element={<NewScan />} />
          <Route path="/scans/:scanId" element={<ScanDetail />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App