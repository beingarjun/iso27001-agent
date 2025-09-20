import { Sidebar } from '@/components/Sidebar'
import { ComplianceDashboard } from '@/components/ComplianceDashboard'

export default function HomePage() {
  return (
    <div className="flex h-screen bg-gray-100">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="py-6">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <h1 className="text-2xl font-semibold text-gray-900">Compliance Dashboard</h1>
          </div>
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <ComplianceDashboard />
          </div>
        </div>
      </main>
    </div>
  )
}