'use client'
import { useState, useEffect } from 'react'
import { ChartBarIcon, ShieldCheckIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline'

interface DashboardStats {
  totalControls: number
  implementedControls: number
  pendingFindings: number
  highRiskFindings: number
}

export function ComplianceDashboard() {
  const [stats, setStats] = useState<DashboardStats>({
    totalControls: 114,
    implementedControls: 89,
    pendingFindings: 23,
    highRiskFindings: 5,
  })

  const implementationRate = Math.round((stats.implementedControls / stats.totalControls) * 100)

  const cards = [
    {
      title: 'Implementation Rate',
      value: `${implementationRate}%`,
      icon: ChartBarIcon,
      color: implementationRate >= 80 ? 'text-green-600' : 'text-yellow-600',
    },
    {
      title: 'Implemented Controls',
      value: `${stats.implementedControls}/${stats.totalControls}`,
      icon: ShieldCheckIcon,
      color: 'text-blue-600',
    },
    {
      title: 'Pending Findings',
      value: stats.pendingFindings,
      icon: ExclamationTriangleIcon,
      color: 'text-orange-600',
    },
    {
      title: 'High Risk Findings',
      value: stats.highRiskFindings,
      icon: ExclamationTriangleIcon,
      color: 'text-red-600',
    },
  ]

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        {cards.map((card) => (
          <div key={card.title} className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <card.icon className={`h-6 w-6 ${card.color}`} />
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">{card.title}</dt>
                    <dd className="text-lg font-medium text-gray-900">{card.value}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900">Recent Activities</h3>
            <div className="mt-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Security scan completed</span>
                <span className="text-xs text-gray-400">2 hours ago</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Control A.8.1.1 updated</span>
                <span className="text-xs text-gray-400">4 hours ago</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">New finding identified</span>
                <span className="text-xs text-gray-400">6 hours ago</span>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900">Pending Approvals</h3>
            <div className="mt-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Risk acceptance for VULN-001</span>
                <button className="text-xs bg-blue-600 text-white px-2 py-1 rounded">Review</button>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Control implementation evidence</span>
                <button className="text-xs bg-blue-600 text-white px-2 py-1 rounded">Review</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}