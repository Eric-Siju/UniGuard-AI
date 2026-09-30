import React from "react"
import {
  LayoutDashboard,
  ShieldAlert,
  Network,
  BrainCircuit,
  RotateCcw,
  FileText,
  Gauge,
  Lock,
  Settings
} from "lucide-react"

export type TabType =
  | "dashboard"
  | "investigation"
  | "flows"
  | "models"
  | "replay"
  | "reports"
  | "benchmark"
  | "compliance"
  | "settings"

interface NavigationProps {
  activeTab: TabType
  onTabChange: (tab: TabType) => void
  alertCount: number
}

export const Navigation: React.FC<NavigationProps> = ({
  activeTab,
  onTabChange,
  alertCount
}) => {
  const tabs = [
    { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    {
      id: "investigation",
      label: "Investigation",
      icon: ShieldAlert,
      badge: alertCount > 0 ? alertCount : null
    },
    { id: "flows", label: "Traffic Analysis", icon: Network },
    { id: "models", label: "ML & Datasets", icon: BrainCircuit },
    { id: "replay", label: "Replay Mode", icon: RotateCcw },
    { id: "reports", label: "Security Reports", icon: FileText },
    { id: "benchmark", label: "Benchmark", icon: Gauge },
    { id: "compliance", label: "Compliance & Diode", icon: Lock },
    { id: "settings", label: "Settings", icon: Settings },
  ]

  return (
    <nav className="bg-slate-950/80 border-b border-slate-800 px-6 overflow-x-auto scrollbar-none">
      <div className="flex items-center space-x-1 min-w-max py-2">
        {tabs.map((tab) => {
          const Icon = tab.icon
          const isActive = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id as TabType)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                isActive
                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-500/10"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? "text-cyan-400" : "text-slate-500"}`} />
              <span>{tab.label}</span>
              {tab.badge && (
                <span className="bg-rose-500/20 text-rose-400 border border-rose-500/40 text-[10px] font-mono px-1.5 py-0.2 rounded-full font-bold">
                  {tab.badge}
                </span>
              )}
            </button>
          )
        })}
      </div>
    </nav>
  )
}
