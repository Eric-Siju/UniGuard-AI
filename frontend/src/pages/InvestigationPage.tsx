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
  ExternalLink,
  Briefcase,
  Tag,
  ShieldCheck,
  Zap,
  Repeat
} from "lucide-react"
import { Alert, FlowRecord } from "../types"
import { fetchAlertDetail, updateAlertLifecycle, createCase } from "../services/api"

interface InvestigationPageProps {
  selectedAlertId: string | null
  alerts: Alert[]
  onBack: () => void
  onSelectAlert: (id: string) => void
  onNavigateToCase?: (caseId: string) => void
}

export const InvestigationPage: React.FC<InvestigationPageProps> = ({
  selectedAlertId,
  alerts,
  onBack,
  onSelectAlert,
  onNavigateToCase
}) => {
  const [currentAlertId, setCurrentAlertId] = useState<string | null>(
    selectedAlertId || (alerts[0]?.alert_id ?? null)
  )
  const [detail, setDetail] = useState<{ alert: Alert; related_flows: FlowRecord[] } | null>(null)
  const [loading, setLoading] = useState<boolean>(false)

  // Lifecycle & Note states
  const [currentStatus, setCurrentStatus] = useState<string>("NEW")
  const [analystNote, setAnalystNote] = useState<string>("")
  const [saveMsg, setSaveMsg] = useState<string>("")
  const [caseCreatedMsg, setCaseCreatedMsg] = useState<string>("")

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
        if (isMounted) {
          setDetail(data)
          setCurrentStatus(data.alert.status || "NEW")
          setAnalystNote(data.alert.analyst_note || "")
        }
      })
      .catch((err) => console.error("Error fetching alert detail:", err))
      .finally(() => {
        if (isMounted) setLoading(false)
      })
    return () => {
      isMounted = false
    }
  }, [currentAlertId])

  const alert = detail?.alert
  const relatedFlows = detail?.related_flows || []

  const handleUpdateStatus = async (newStatus: string) => {
    if (!alert) return
    try {
      await updateAlertLifecycle(alert.alert_id, {
        status: newStatus,
        analyst_note: analystNote
      })
      setCurrentStatus(newStatus)
      setSaveMsg(`Lifecycle updated to ${newStatus}`)
      setTimeout(() => setSaveMsg(""), 3000)
    } catch (err) {
      console.error(err)
    }
  }

  const handleSaveNote = async () => {
    if (!alert) return
    try {
      await updateAlertLifecycle(alert.alert_id, {
        analyst_note: analystNote
      })
      setSaveMsg("Analyst note saved.")
      setTimeout(() => setSaveMsg(""), 3000)
    } catch (err) {
      console.error(err)
    }
  }

  const handleCreateCaseFromAlert = async () => {
    if (!alert) return
    try {
      const res = await createCase({
        title: `Investigation: ${alert.threat_type} from ${alert.src_ip}`,
        description: `Correlated forensic incident for alert ${alert.alert_id} (${alert.threat_type}). Target: ${alert.dst_ip}:${alert.dst_port}`,
        severity: alert.severity,
        related_alerts: [alert.alert_id],
        related_assets: [alert.src_ip, alert.dst_ip],
        tags: ["SIH26145", alert.threat_type.replace(/\s+/g, "-")],
        analyst_note: analystNote || `Escalated directly from alert ${alert.alert_id}`
      })
      setCaseCreatedMsg(`Case created: ${res.case_id}`)
      if (onNavigateToCase) {
        setTimeout(() => onNavigateToCase(res.case_id), 1000)
      }
    } catch (err) {
      console.error(err)
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
              Deep forensic correlation, multi-signal consensus, MITRE ATT&CK mapping, and SOC case escalation
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
        <div className="space-y-6">
          {/* Multi-Signal Detection Pipeline Visualization */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-2 font-bold">
              Multi-Signal Detection Pipeline Consensus
            </span>
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
              <div className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span> Passive Traffic
              </div>
              <span className="text-slate-600">→</span>
              <div className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span> 26 Features
              </div>
              <span className="text-slate-600">→</span>
              <div className="px-3 py-1.5 rounded-lg bg-cyan-950/50 border border-cyan-800 text-cyan-300 font-bold flex items-center gap-1.5">
                <CheckCircle className="w-3 h-3 text-cyan-400" /> Rule Engine: MATCH
              </div>
              <span className="text-slate-600">→</span>
              <div className="px-3 py-1.5 rounded-lg bg-blue-950/50 border border-blue-800 text-blue-300 font-bold flex items-center gap-1.5">
                <Brain className="w-3 h-3 text-blue-400" /> Random Forest:{" "}
                {alert.ml_confidence ? `${(alert.ml_confidence * 100).toFixed(0)}%` : "CORROBORATED"}
              </div>
              <span className="text-slate-600">→</span>
              <div className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 flex items-center gap-1.5">
                <Activity className="w-3 h-3 text-purple-400" /> Isolation Forest
              </div>
              <span className="text-slate-600">→</span>
              <div className="px-3 py-1.5 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-300 font-bold flex items-center gap-1.5">
                <Zap className="w-3 h-3 text-rose-400" /> Correlated Alert
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left Column: Primary Threat Dossier (7 cols) */}
            <div className="lg:col-span-7 space-y-6">
              {/* Incident Summary Card */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
                  <div>
                    <span className="text-[11px] font-mono text-slate-400 uppercase">
                      Alert Reference
                    </span>
                    <div className="text-lg font-extrabold text-white font-mono">
                      {alert.alert_id}
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`px-2.5 py-1 rounded-md text-xs font-bold border ${getSeverityBadge(
                        alert.severity
                      )}`}
                    >
                      {alert.severity} SEVERITY
                    </span>
                    <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-cyan-950/60 border border-cyan-800 text-cyan-300">
                      {(alert.confidence * 100).toFixed(0)}% CONFIDENCE
                    </span>
                    {alert.occurrences && alert.occurrences > 1 && (
                      <span className="px-2 py-1 rounded-md text-xs font-mono font-bold bg-amber-950/60 border border-amber-800 text-amber-300 flex items-center gap-1">
                        <Repeat className="w-3 h-3" /> {alert.occurrences}x ({alert.suppressed_count} suppressed)
                      </span>
                    )}
                  </div>
                </div>

                {/* MITRE ATT&CK Mapping Card */}
                {alert.mitre_technique_id && (
                  <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">
                        MITRE ATT&CK Technique
                      </span>
                      <div className="text-xs font-bold text-slate-200 mt-0.5">
                        <span className="text-cyan-400 font-mono">{alert.mitre_technique_id}</span> &bull;{" "}
                        {alert.mitre_technique_name}
                      </div>
                    </div>
                    <span className="px-2.5 py-1 rounded text-xs font-mono font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                      TACTIC: {alert.mitre_tactic}
                    </span>
                  </div>
                )}

                {/* Endpoint 5-Tuple Box */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950/70 p-3.5 rounded-xl border border-slate-800/80 font-mono text-xs">
                  <div>
                    <div className="text-slate-500 uppercase text-[10px]">Source Host</div>
                    <div className="text-cyan-300 font-bold mt-0.5">{alert.src_ip}</div>
                  </div>
                  <div>
                    <div className="text-slate-500 uppercase text-[10px]">Destination Target</div>
                    <div className="text-rose-300 font-bold mt-0.5">
                      {alert.dst_ip}:{alert.dst_port}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500 uppercase text-[10px]">Transport Protocol</div>
                    <div className="text-slate-200 font-bold mt-0.5">{alert.protocol}</div>
                  </div>
                  <div>
                    <div className="text-slate-500 uppercase text-[10px]">Total Payload Volume</div>
                    <div className="text-slate-200 font-bold mt-0.5">
                      {(alert.total_bytes / 1024).toFixed(1)} KB ({alert.total_packets} pkts)
                    </div>
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
                      <div className="text-xs text-slate-500 italic">
                        No detailed rule evidence logged.
                      </div>
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
                      <span className="text-xs text-slate-500 font-mono">
                        None (Anomaly/ML detection only)
                      </span>
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
                          <td className="py-2 px-2 text-slate-400 truncate max-w-[120px]">
                            {f.flow_id}
                          </td>
                          <td className="py-2 px-2 text-slate-300">{f.protocol}</td>
                          <td className="py-2 px-2 text-slate-300">
                            {f.total_bytes} bytes ({f.total_packets}p)
                          </td>
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

            {/* Right Column: Explainable AI & SOC Case Escalation (5 cols) */}
            <div className="lg:col-span-5 space-y-6">
              {/* Analyst Triage & Lifecycle Controls */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
                <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                  <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                    Analyst Triage & Lifecycle
                  </span>
                  <span className="text-xs font-mono font-bold text-cyan-400">
                    STATUS: {currentStatus}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  {["NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"].map((st) => (
                    <button
                      key={st}
                      onClick={() => handleUpdateStatus(st)}
                      className={`py-1.5 px-3 rounded-lg text-xs font-bold font-mono transition-all cursor-pointer ${
                        currentStatus === st
                          ? "bg-cyan-600 text-slate-950"
                          : "bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800"
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>

                {/* Analyst Notes */}
                <div className="space-y-2 pt-2">
                  <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
                    Analyst Investigation Note
                  </label>
                  <textarea
                    rows={3}
                    placeholder="Enter forensic triage notes, IOC notes, or disposition..."
                    value={analystNote}
                    onChange={(e) => setAnalystNote(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
                  />
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-emerald-400 font-mono">{saveMsg}</span>
                    <button
                      onClick={handleSaveNote}
                      className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
                    >
                      Save Note
                    </button>
                  </div>
                </div>

                {/* Escalate to Case Button */}
                <div className="pt-2 border-t border-slate-800">
                  <button
                    onClick={handleCreateCaseFromAlert}
                    className="w-full py-2.5 bg-gradient-to-r from-amber-600 to-yellow-600 hover:from-amber-500 hover:to-yellow-500 text-slate-950 font-extrabold text-xs rounded-xl transition-all shadow-md shadow-amber-500/10 flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <Briefcase className="w-4 h-4 fill-current" />
                    Escalate to SOC Incident Case
                  </button>
                  {caseCreatedMsg && (
                    <span className="text-xs text-amber-300 font-mono text-center block mt-1.5">
                      {caseCreatedMsg}
                    </span>
                  )}
                </div>
              </div>

              {/* Risk Gauge Card */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-3 flex items-center gap-1.5">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  Aggregated Risk Calculation
                </h3>
                <div className="flex items-center justify-center p-4">
                  <div className="relative w-36 h-36 rounded-full border-4 border-slate-800 flex items-center justify-center bg-slate-950">
                    <div className="text-center">
                      <div className="text-3xl font-extrabold text-rose-400 font-mono">
                        {alert.risk_score}
                      </div>
                      <div className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                        Risk Index
                      </div>
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
                      <div
                        key={i}
                        className="bg-slate-950/70 p-3 rounded-xl border border-slate-800/80 space-y-1.5"
                      >
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-semibold text-slate-200">{feat.name}</span>
                          <span className="font-mono text-cyan-400 font-bold">
                            Impact: {feat.impact.toFixed(3)}
                          </span>
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
                    <div className="text-xs text-slate-500 italic">
                      No feature attribution data recorded.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
