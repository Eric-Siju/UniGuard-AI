import React, { useState, useEffect } from "react"
import { Header } from "./components/Header"
import { Navigation, TabType } from "./components/Navigation"
import { DashboardPage } from "./pages/DashboardPage"
import { InvestigationPage } from "./pages/InvestigationPage"
import { TrafficAnalysisPage } from "./pages/TrafficAnalysisPage"
import { ThreatHuntPage } from "./pages/ThreatHuntPage"
import { AssetsPage } from "./pages/AssetsPage"
import { CasesPage } from "./pages/CasesPage"
import { CampaignsPage } from "./pages/CampaignsPage"
import { ThreatIntelPage } from "./pages/ThreatIntelPage"
import { ModelPage } from "./pages/ModelPage"
import { ReplayPage } from "./pages/ReplayPage"
import { ReportPage } from "./pages/ReportPage"
import { BenchmarkPage } from "./pages/BenchmarkPage"
import { DataSourcesPage } from "./pages/DataSourcesPage"
import { CompliancePage } from "./pages/CompliancePage"
import { SettingsPage } from "./pages/SettingsPage"
import { JudgeModeModal } from "./components/JudgeModeModal"

import { SystemStats, Alert, ThreatSummary } from "./types"
import {
  fetchStats,
  fetchAlerts,
  fetchThreatsSummary,
  createAlertsWebSocket
} from "./services/api"

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>("dashboard")
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null)
  const [huntSearchIp, setHuntSearchIp] = useState<string>("")
  const [isJudgeModeOpen, setIsJudgeModeOpen] = useState<boolean>(false)
  
  const [stats, setStats] = useState<SystemStats>({
    flows_processed: 0,
    packets_processed: 0,
    threats_detected: 0,
    suspicious_flows: 0,
    current_risk_level: "LOW",
    processing_latency_ms: 12.0,
    packets_per_sec: 0,
    flows_per_sec: 0,
    cpu_percent: 0,
    memory_mb: 0,
    passive_mode: true,
    read_only_status: true,
    active_response: false
  })
  
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [threatSummary, setThreatSummary] = useState<ThreatSummary | null>(null)
  const [liveChartData, setLiveChartData] = useState<Array<{ time: string; pps: number; bps: number }>>([
    { time: "00:00", pps: 0, bps: 0 }
  ])
  
  const [streamState, setStreamState] = useState<string>("STOPPED")
  const [streamSpeed, setStreamSpeed] = useState<number>(1.0)
  const [activeScenario, setActiveScenario] = useState<string>("combined_demo")
  const [wsConnected, setWsConnected] = useState<boolean>(false)

  // Initial data load
  useEffect(() => {
    fetchStats().then(setStats).catch(console.error)
    fetchAlerts({ limit: 50 }).then((res) => setAlerts(res.items)).catch(console.error)
    fetchThreatsSummary().then(setThreatSummary).catch(console.error)
  }, [])

  // Real-time WebSocket connection
  useEffect(() => {
    const ws = createAlertsWebSocket(
      (event) => {
        if (event.type === "flow_event") {
          const nowStr = new Date().toLocaleTimeString("en-US", {
            hour12: false,
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
          })
          
          const newPps = event.flow?.total_packets ? event.flow.total_packets * 8 : Math.floor(Math.random() * 40 + 20)
          const newBps = event.flow?.total_bytes ? event.flow.total_bytes * 8 : 15000

          setLiveChartData((prev) => {
            const next = [...prev, { time: nowStr, pps: newPps, bps: newBps }]
            return next.length > 20 ? next.slice(next.length - 20) : next
          })

          if (event.alert) {
            setAlerts((prev) => [event.alert, ...prev.slice(0, 49)])
            // Refresh threat summary counts dynamically
            fetchThreatsSummary().then(setThreatSummary).catch(() => {})
          }
        } else if (event.type === "stats_update") {
          if (event.stats) {
            setStats((prev) => ({
              ...prev,
              ...event.stats,
              packets_per_sec: event.stats.current_fps ? event.stats.current_fps * 15 : prev.packets_per_sec,
              flows_per_sec: event.stats.current_fps || prev.flows_per_sec
            }))
          }
        } else if (event.type === "init_status") {
          if (event.state) setStreamState(event.state)
          if (event.speed) setStreamSpeed(event.speed)
          if (event.scenario) setActiveScenario(event.scenario)
          if (event.stats) setStats((prev) => ({ ...prev, ...event.stats }))
        }
      },
      (connected) => setWsConnected(connected)
    )

    return () => {
      ws.disconnect()
    }
  }, [])

  const handleSelectAlert = (alertId: string) => {
    setSelectedAlertId(alertId)
    setActiveTab("investigation")
  }

  const handleNavigateToHunt = (ip: string) => {
    setHuntSearchIp(ip)
    setActiveTab("hunt")
  }

  const handleStreamStateChange = (state: string, scenario: string, speed: number) => {
    setStreamState(state)
    setActiveScenario(scenario)
    setStreamSpeed(speed)
  }

  return (
    <div className="min-h-screen bg-[#050811] text-slate-100 flex flex-col font-['Plus_Jakarta_Sans',sans-serif]">
      {/* Top Header */}
      <Header
        streamState={streamState}
        streamSpeed={streamSpeed}
        activeScenario={activeScenario}
        wsConnected={wsConnected}
        onStreamStateChange={handleStreamStateChange}
        onOpenJudgeMode={() => setIsJudgeModeOpen(true)}
      />

      {/* Primary Tab Navigation */}
      <Navigation
        activeTab={activeTab}
        onTabChange={setActiveTab}
        alertCount={alerts.length}
      />

      {/* Main Content View */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto p-4">
        {activeTab === "dashboard" && (
          <DashboardPage
            stats={stats}
            alerts={alerts}
            threatSummary={threatSummary}
            liveChartData={liveChartData}
            onSelectAlert={handleSelectAlert}
          />
        )}

        {activeTab === "investigation" && (
          <InvestigationPage
            selectedAlertId={selectedAlertId}
            alerts={alerts}
            onBack={() => setActiveTab("dashboard")}
            onSelectAlert={(id) => setSelectedAlertId(id)}
            onNavigateToCase={() => setActiveTab("cases")}
          />
        )}

        {activeTab === "flows" && <TrafficAnalysisPage />}

        {activeTab === "hunt" && (
          <ThreatHuntPage
            initialSearchIp={huntSearchIp}
            onSelectAlert={handleSelectAlert}
            onSelectAsset={handleNavigateToHunt}
          />
        )}

        {activeTab === "assets" && (
          <AssetsPage
            onNavigateToHunt={handleNavigateToHunt}
          />
        )}

        {activeTab === "cases" && <CasesPage />}

        {activeTab === "campaigns" && (
          <CampaignsPage
            onSelectAlert={handleSelectAlert}
            onSelectAsset={handleNavigateToHunt}
          />
        )}

        {activeTab === "threat-intel" && <ThreatIntelPage />}

        {activeTab === "models" && <ModelPage />}

        {activeTab === "replay" && (
          <ReplayPage
            streamState={streamState}
            streamSpeed={streamSpeed}
            activeScenario={activeScenario}
            flowsStreamed={stats.flows_processed}
            threatsStreamed={stats.threats_detected}
            onStateChange={handleStreamStateChange}
          />
        )}

        {activeTab === "reports" && <ReportPage />}

        {activeTab === "benchmark" && <BenchmarkPage />}

        {activeTab === "datasources" && <DataSourcesPage />}

        {activeTab === "compliance" && <CompliancePage />}

        {activeTab === "settings" && <SettingsPage />}
      </main>

      {/* Judge Mode Modal */}
      <JudgeModeModal
        isOpen={isJudgeModeOpen}
        onClose={() => setIsJudgeModeOpen(false)}
        onNavigateTab={(tab) => setActiveTab(tab)}
        onStreamStateChange={handleStreamStateChange}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 px-6 py-4 text-center text-xs text-slate-500 font-mono">
        UniGuard AI &bull; Smart India Hackathon 2026 (SIH26145) &bull; Air-Gapped Passive Unidirectional Defense System
      </footer>
    </div>
  )
}

