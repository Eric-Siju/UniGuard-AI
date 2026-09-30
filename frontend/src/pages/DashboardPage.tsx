import React from "react"
import {
  Activity,
  AlertTriangle,
  ShieldAlert,
  Zap,
  Clock,
  ArrowUpRight,
  TrendingUp,
  Cpu,
  Layers,
  ChevronRight
} from "lucide-react"
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid
} from "recharts"
import { SystemStats, Alert, ThreatSummary } from "../types"

interface DashboardPageProps {
  stats: SystemStats
  alerts: Alert[]
  threatSummary: ThreatSummary | null
  liveChartData: Array<{ time: string; pps: number; bps: number }>
  onSelectAlert: (alertId: string) => void
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  stats,
  alerts,
  threatSummary,
  liveChartData,
  onSelectAlert
}) => {
  const getRiskColor = (level: string) => {
    switch (level) {
      case "CRITICAL": return "text-rose-400 bg-rose-950/60 border-rose-800"
      case "HIGH": return "text-orange-400 bg-orange-950/60 border-orange-800"
      case "MEDIUM": return "text-amber-400 bg-amber-950/60 border-amber-800"
      default: return "text-emerald-400 bg-emerald-950/60 border-emerald-800"
    }
  }

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-rose-500/20 text-rose-300 border-rose-500/40"
      case "HIGH":
        return "bg-orange-500/20 text-orange-300 border-orange-500/40"
      case "MEDIUM":
        return "bg-amber-500/20 text-amber-300 border-amber-500/40"
      default:
        return "bg-sky-500/20 text-sky-300 border-sky-500/40"
    }
  }

  // Build threat distribution chart data
  const threatChartData = threatSummary?.threat_distribution
    ? Object.entries(threatSummary.threat_distribution).map(([name, count]) => ({
        name: name.replace("Suspicious ", "").replace(" / DNS Tunneling", ""),
        count
      }))
    : [
        { name: "DDoS", count: 0 },
        { name: "Port Scan", count: 0 },
        { name: "Botnet C2", count: 0 },
        { name: "DGA/DNS", count: 0 },
        { name: "Encrypted", count: 0 },
        { name: "Exfiltration", count: 0 }
      ]

  return (
    <div className="space-y-6 p-6">
      {/* 6 Top Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {/* Card 1: Flows Processed */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-lg backdrop-blur">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Flows Processed</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-extrabold text-white mt-2 font-mono">
            {stats.flows_processed.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
            <span className="text-cyan-400 font-bold">{stats.flows_per_sec.toFixed(1)}</span> flows/sec
          </div>
        </div>

        {/* Card 2: Packets / sec */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-lg backdrop-blur">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Packet Velocity</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-extrabold text-white mt-2 font-mono">
            {stats.packets_per_sec.toLocaleString(undefined, { maximumFractionDigits: 0 })}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Total pkts: <span className="font-mono text-slate-300">{stats.packets_processed.toLocaleString()}</span>
          </div>
        </div>

        {/* Card 3: Threats Detected */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-lg backdrop-blur relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Threats Detected</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-extrabold text-rose-400 mt-2 font-mono flex items-center gap-2">
            {stats.threats_detected.toLocaleString()}
            {stats.threats_detected > 0 && (
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500"></span>
              </span>
            )}
          </div>
          <div className="text-[11px] text-rose-400/80 mt-1">Multi-signal verified</div>
        </div>

        {/* Card 4: Suspicious Outliers */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-lg backdrop-blur">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Suspicious Outliers</span>
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
          </div>
          <div className="text-2xl font-extrabold text-yellow-300 mt-2 font-mono">
            {stats.suspicious_flows.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Isolation Forest flags</div>
        </div>

        {/* Card 5: Current Risk Level */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-lg backdrop-blur">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Risk Level</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2">
            <span className={`inline-block px-2.5 py-1 text-sm font-extrabold rounded-md border ${getRiskColor(stats.current_risk_level)}`}>
              {stats.current_risk_level}
            </span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Dynamic SOC Threat Level</div>
        </div>

        {/* Card 6: Processing Latency */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-lg backdrop-blur">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Pipeline Latency</span>
            <Clock className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-extrabold text-white mt-2 font-mono">
            {stats.processing_latency_ms.toFixed(1)} <span className="text-xs font-normal text-slate-400">ms</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1.5">
            <Cpu className="w-3 h-3 text-cyan-400" />
            <span>CPU: {stats.cpu_percent}%</span>
            <span>RAM: {stats.memory_mb.toFixed(0)}MB</span>
          </div>
        </div>
      </div>

      {/* Real-Time Visual Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Live Traffic Velocity Chart (7 cols) */}
        <div className="lg:col-span-7 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-cyan-400" />
                Live Unidirectional Traffic Rate
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">Real-time packet velocity observed via passive TAP</p>
            </div>
            <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/80 px-2 py-0.5 rounded">
              WINDOW: 20 SAMPLES
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={liveChartData}>
                <defs>
                  <linearGradient id="ppsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0b1120",
                    borderColor: "#334155",
                    borderRadius: "8px",
                    color: "#f8fafc",
                    fontSize: "12px"
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="pps"
                  name="Packets/sec"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#ppsGradient)"
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Distribution Chart (5 cols) */}
        <div className="lg:col-span-5 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Detected Threat Classes
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">Classification across 6 required threat categories</p>
            </div>
            <span className="text-[11px] font-mono text-rose-400 bg-rose-950/60 border border-rose-800/80 px-2 py-0.5 rounded">
              TOTAL: {stats.threats_detected}
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={threatChartData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis dataKey="name" type="category" stroke="#94a3b8" tick={{ fontSize: 11 }} width={90} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0b1120",
                    borderColor: "#334155",
                    borderRadius: "8px",
                    color: "#f8fafc",
                    fontSize: "12px"
                  }}
                />
                <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Live Threat Alert Feed Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Live Security Incidents Feed
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Correlated alerts from Rules, Random Forest, and Anomaly Detection
            </p>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            Showing latest {alerts.slice(0, 10).length} alerts
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-semibold">
                <th className="py-2.5 px-3">Alert ID</th>
                <th className="py-2.5 px-3">Threat Type</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3">Endpoints</th>
                <th className="py-2.5 px-3">Primary Evidence</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    No active threats detected. Monitoring unidirectional traffic passively...
                  </td>
                </tr>
              ) : (
                alerts.slice(0, 10).map((a) => (
                  <tr key={a.alert_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-3 text-slate-400 font-medium">{a.alert_id}</td>
                    <td className="py-3 px-3 font-semibold text-slate-100 font-sans">{a.threat_type}</td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(a.severity)}`}>
                        {a.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-cyan-400 font-bold">
                      {(a.confidence * 100).toFixed(0)}%
                    </td>
                    <td className="py-3 px-3 text-slate-300">
                      {a.src_ip} &rarr; {a.dst_ip}:{a.dst_port}
                    </td>
                    <td className="py-3 px-3 font-sans text-slate-300 max-w-xs truncate">
                      {a.evidence && a.evidence.length > 0 ? a.evidence[0] : "Multi-signal anomaly"}
                    </td>
                    <td className="py-3 px-3 text-right font-sans">
                      <button
                        onClick={() => onSelectAlert(a.alert_id)}
                        className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-bold hover:underline cursor-pointer"
                      >
                        Investigate <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
