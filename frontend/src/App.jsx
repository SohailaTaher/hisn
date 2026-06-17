import { BrowserRouter, Routes, Route } from 'react-router-dom'
import ScansList from './pages/ScansList'
import ScanDetail from './pages/ScanDetail'
import NewScan from './pages/NewScan'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<ScansList />} />
        <Route path="/scans/new" element={<NewScan />} />     {/* 👈 NEW */}
        <Route path="/scans/:scanId" element={<ScanDetail />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App