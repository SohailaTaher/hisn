import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './pages/Layout'
import ScansList from './pages/ScansList'
import ScanDetail from './pages/ScanDetail'
import NewScan from './pages/NewScan'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<ScansList />} />
          <Route path="/scans/new" element={<NewScan />} />
          <Route path="/scans/:scanId" element={<ScanDetail />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App