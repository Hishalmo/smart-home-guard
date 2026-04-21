import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { DashboardPage } from '@/pages/DashboardPage'
import './index.css'

// TEMP: mock-data preview. Restore App/BrowserRouter/QueryClientProvider once auth + backend are wired.
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <DashboardPage />
  </StrictMode>,
)
