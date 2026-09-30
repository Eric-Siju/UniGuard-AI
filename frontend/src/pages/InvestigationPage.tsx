import React, { useState, useEffect } from "react"
import {
  ShieldAlert,
  ArrowLeft,
  CheckCircle,
  AlertTriangle,
  Brain,
  ListFilter,
  Clock,
  Layers,
  Activity,
  Server,
  Terminal,
  ExternalLink
} from "lucide-react"
import { Alert, FlowRecord } from "../types"
import { fetchAlertDetail } from "../services/api"

interface InvestigationPageProps {
  selectedAlertId: string | null
  alerts: Alert[]
  onBack: () => void
  onSelectAlert: (id: string) => void
}

export const InvestigationPage: React.FC<InvestigationPageProps> = ({
  selectedAlertId,
  alerts,
  onBack,
  onSelectAlert
}) => {
  const [currentAlertId, setCurrentAlertId] = useState<string | null>(selectedAlertId || (alerts[0]?.alert_id ?? null))
  const [detail, setDetail] = useState<{ alert: Alert; related_flows: FlowRecord[] } | null>(null)
  const [loading, setLoading] = useState<boolean>(false)

  useEffect(() => {
    if (selectedAlertId) {
      setCurrentAlertId(selectedAlertId)
    } else if (!currentAlertId && alerts.length > 0) {
      setCurrentAlertId(alerts[0].alert_id)
    }
  }, [selectedAlertId, alerts])

  useEffect(() => {
    if (!currentAlertId) return
    let isMounted = true
    setLoading(true)
    fetchAlertDetail(currentAlertId)
      .then((data) => {
        if (isMounted) setDetail(data)
      })
      .catch((err) => console.error("Error fetching alert detail:", err))
      .finally(() => {
        if (isMounted) setLoading(false)
      })
    return () => { isMounted = false }
  }, [currentAlertId])

  const alert = detail?.alert
  const relatedFlows = detail?.related_flows || []

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

  return (
    <div className="space-y-6 p-6">
      {/* Top Header & Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 rounded-2xl p-4 shadow-xl">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <h1 className="text-base font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              Security Incident Investigation Console
            </h1>
            <p className="text-xs text-slate-400">
              Deep forensic correlation, explainable feature attribution, and contextual flow timeline
            </p>
          </div>
        </div>

        {/* Quick Alert Switcher Dropdown */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-mono">Select Alert:</span>
          <select
            value={currentAlertId || ""}
            onChange={(e) => {
              setCurrentAlertId(e.target.value)
              onSelectAlert(e.target.value)
            }}
            className="bg-slate-950 text-xs font-mono text-cyan-300 border border-slate-700 rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            {alerts.map((a) => (
              <option key={a.alert_id} value={a.alert_id}>
                {a.alert_id} &bull; {a.threat_type} ({a.severity})
              </option>
            ))}
          </select>
        </div>
      </div>

      {loading && (
        <div className="text-center py-16 text-cyan-400 font-mono text-sm animate-pulse">
          Loading threat forensics & correlated evidence...
        </div>
      )}

      {!loading && !alert && (
        <div className="text-center py-16 bg-slate-900/40 rounded-2xl border border-slate-800 text-slate-400">
          No incident selected. Select an incident from the Dashboard alert feed to investigate.
        </div>
      )}

      {!loading && alert && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Primary Threat Dossier (7 cols) */}
          <div className="lg:col-span-7 space-y-6">
            {/* Incident Summary Card */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
                <div>
                  <span className="text-[11px] font-mono text-slate-400 uppercase">Alert Reference</span>
                  <div className="text-lg font-extrabold text-white font-mono">{alert.alert_id}</div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded-md text-xs font-bold border ${getSeverityBadge(alert.severity)}`}>
                    {alert.severity} SEVERITY
                  </span>
                  <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-cyan-950/60 border border-cyan-800 text-cyan-300">
                    {(alert.confidence * 100).toFixed(0)}% CONFIDENCE
                  </span>
                </div>
              </div>

              {/* Endpoint 5-Tuple Box */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950/70 p-3.5 rounded-xl border border-slate-800/80 font-mono text-xs">
                <div>
                  <div className="text-slate-500 uppercase text-[10px]">Source Host</div>
                  <div className="text-cyan-300 font-bold mt-0.5">{alert.src_ip}</div>
                </div>
                <div>
                  <div className="text-slate-500 uppercase text-[10px]">Destination Target</div>
                  <div className="text-rose-300 font-bold mt-0.5">{alert.dst_ip}:{alert.dst_port}</div>
                </div>
                <div>
                  <div className="text-slate-500 uppercase text-[10px]">Transport Protocol</div>
                  <div className="text-slate-200 font-bold mt-0.5">{alert.protocol}</div>
                </div>
                <div>
                  <div className="text-slate-500 uppercase text-[10px]">Total Payload Volume</div>
                  <div className="text-slate-200 font-bold mt-0.5">{(alert.total_bytes / 1024).toFixed(1)} KB ({alert.total_packets} pkts)</div>
                </div>
              </div>

              {/* Transparent Evidence Log */}
              <div>
                <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                  Corroborating Evidence & Behavioral Signals
                </h3>
                <div className="space-y-2">
                  {alert.evidence && alert.evidence.length > 0 ? (
                    alert.evidence.map((ev, i) => (
                      <div
                        key={i}
                        className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs text-slate-200 leading-relaxed font-sans"
                      >
                        {ev}
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-500 italic">No detailed rule evidence logged.</div>
                  )}
                </div>
              </div>

              {/* Rule Engine Results */}
              <div>
                <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  Triggered Heuristic Rules
                </h3>
                <div className="flex flex-wrap gap-2">
                  {alert.rule_matches && alert.rule_matches.length > 0 ? (
                    alert.rule_matches.map((r, i) => (
                      <span
                        key={i}
                        className="px-2.5 py-1 rounded bg-slate-800 text-cyan-300 border border-cyan-800/50 font-mono text-xs"
                      >
                        {r}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-slate-500 font-mono">None (Anomaly/ML detection only)</span>
                  )}
                </div>
              </div>
            </div>

            {/* Contextual Flow Timeline */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Clock className="w-4 h-4 text-cyan-400" />
                Contextual Flow Timeline Around Incident
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 uppercase font-semibold">
                      <th className="py-2 px-2">Flow ID</th>
                      <th className="py-2 px-2">Protocol</th>
                      <th className="py-2 px-2">Volume</th>
                      <th className="py-2 px-2">Classification</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                    {relatedFlows.map((f, i) => (
                      <tr key={i} className="hover:bg-slate-800/40">
                        <td className="py-2 px-2 text-slate-400 truncate max-w-[120px]">{f.flow_id}</td>
                        <td className="py-2 px-2 text-slate-300">{f.protocol}</td>
                        <td className="py-2 px-2 text-slate-300">{f.total_bytes} bytes ({f.total_packets}p)</td>
                        <td className="py-2 px-2">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] ${
                              f.threat_label === "Normal"
                                ? "bg-slate-800 text-slate-400"
                                : "bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold"
                            }`}
                          >
                            {f.threat_label}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Right Column: Explainable AI & Risk Score (5 cols) */}
          <div className="lg:col-span-5 space-y-6">
            {/* Risk Gauge Card */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Activity className="w-4 h-4 text-cyan-400" />
                Aggregated Risk Calculation
              </h3>
              <div className="flex items-center justify-center p-4">
                <div className="relative w-36 h-36 rounded-full border-4 border-slate-800 flex items-center justify-center bg-slate-950">
                  <div className="text-center">
                    <div className="text-3xl font-extrabold text-rose-400 font-mono">{alert.risk_score}</div>
                    <div className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Risk Index</div>
                  </div>
                </div>
              </div>
              <div className="text-xs text-slate-400 text-center px-4">
                Transparent score synthesizing base threat severity, volumetric impact, and model confidence corroboration.
              </div>
            </div>

            {/* Explainable AI (XAI) Attribution */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
              <div>
                <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                  <Brain className="w-4 h-4 text-cyan-400" />
                  Explainable AI (XAI) Feature Attribution
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Top statistical feature deviations driving Random Forest classification
                </p>
              </div>

              <div className="space-y-3">
                {alert.contributing_features && alert.contributing_features.length > 0 ? (
                  alert.contributing_features.map((feat, i) => (
                    <div key={i} className="bg-slate-950/70 p-3 rounded-xl border border-slate-800/80 space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-slate-200">{feat.name}</span>
                        <span className="font-mono text-cyan-400 font-bold">Impact: {feat.impact.toFixed(3)}</span>
                      </div>
                      <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                        <div
                          className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full rounded-full"
                          style={{ width: `${Math.min(feat.impact * 100, 100)}%` }}
                        ></div>
                      </div>
                      <div className="flex justify-between text-[10px] text-slate-400 font-mono">
                        <span>Observed Value: {feat.value.toFixed(2)}</span>
                        <span>Feature Weight: {feat.importance.toFixed(3)}</span>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-slate-500 italic">No feature attribution data recorded.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
