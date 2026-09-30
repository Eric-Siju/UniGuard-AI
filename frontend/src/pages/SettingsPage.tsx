import React, { useState, useEffect } from "react"
import { Settings as SettingsIcon, Save, RefreshCw, CheckCircle2, Sliders, Shield } from "lucide-react"
import { fetchSettings, updateSettings } from "../services/api"

export const SettingsPage: React.FC = () => {
  const [config, setConfig] = useState<any>({
    ddos_packet_rate_threshold: 250.0,
    ddos_syn_ratio_threshold: 0.80,
    port_scan_port_threshold: 15,
    botnet_interval_jitter_max: 0.20,
    dns_entropy_threshold: 3.5,
    dns_length_threshold: 28,
    exfiltration_bytes_threshold: 4000000,
    stream_interval: 0.6
  })
  const [loading, setLoading] = useState<boolean>(true)
  const [savedMessage, setSavedMessage] = useState<string | null>(null)

  useEffect(() => {
    fetchSettings()
      .then((data) => {
        if (data) setConfig((prev: any) => ({ ...prev, ...data }))
      })
      .catch((err) => console.error("Error fetching settings:", err))
      .finally(() => setLoading(false))
  }, [])

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setSavedMessage(null)
    try {
      await updateSettings(config)
      setSavedMessage("Detection sensitivity thresholds updated successfully.")
      setTimeout(() => setSavedMessage(null), 4000)
    } catch (err: any) {
      alert("Failed to save settings: " + err.message)
    }
  }

  return (
    <div className="space-y-6 p-6">
      {/* Top Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <SettingsIcon className="w-5 h-5 text-cyan-400" />
            Detection Sensitivity & Pipeline Configuration
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Fine-tune multi-signal rule heuristics, anomaly sensitivity, and simulation parameters
          </p>
        </div>
      </div>

      {savedMessage && (
        <div className="p-4 bg-emerald-950/60 border border-emerald-800 rounded-xl text-xs font-mono text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{savedMessage}</span>
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Section 1: DDoS & Flood Thresholds */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2 border-b border-slate-800 pb-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              DDoS & Flooding Heuristics
            </h2>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                DDoS Packet Rate Threshold (pkts/sec)
              </label>
              <input
                type="number"
                step="10"
                value={config.ddos_packet_rate_threshold}
                onChange={(e) => setConfig({ ...config, ddos_packet_rate_threshold: parseFloat(e.target.value) })}
                className="w-full bg-slate-950 text-xs text-white border border-slate-700 rounded-lg p-2.5 font-mono focus:border-cyan-500"
              />
              <span className="text-[10px] text-slate-500">Flows exceeding this packet velocity trigger high-confidence flood alert</span>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                SYN Ratio Threshold (0.0 - 1.0)
              </label>
              <input
                type="number"
                step="0.05"
                min="0.5"
                max="1.0"
                value={config.ddos_syn_ratio_threshold}
                onChange={(e) => setConfig({ ...config, ddos_syn_ratio_threshold: parseFloat(e.target.value) })}
                className="w-full bg-slate-950 text-xs text-white border border-slate-700 rounded-lg p-2.5 font-mono focus:border-cyan-500"
              />
              <span className="text-[10px] text-slate-500">Proportion of SYN flags indicating uncompleted handshakes</span>
            </div>
          </div>

          {/* Section 2: Reconnaissance & Botnet */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2 border-b border-slate-800 pb-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Reconnaissance & C2 Beaconing
            </h2>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Port Scan Port Threshold (Unique Ports)
              </label>
              <input
                type="number"
                value={config.port_scan_port_threshold}
                onChange={(e) => setConfig({ ...config, port_scan_port_threshold: parseInt(e.target.value) })}
                className="w-full bg-slate-950 text-xs text-white border border-slate-700 rounded-lg p-2.5 font-mono focus:border-cyan-500"
              />
              <span className="text-[10px] text-slate-500">Distinct destination ports contacted before flagging horizontal/vertical scan</span>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Botnet Heartbeat Jitter Max (std dev sec)
              </label>
              <input
                type="number"
                step="0.02"
                value={config.botnet_interval_jitter_max}
                onChange={(e) => setConfig({ ...config, botnet_interval_jitter_max: parseFloat(e.target.value) })}
                className="w-full bg-slate-950 text-xs text-white border border-slate-700 rounded-lg p-2.5 font-mono focus:border-cyan-500"
              />
              <span className="text-[10px] text-slate-500">Maximum inter-arrival variance allowed for periodic C2 beaconing</span>
            </div>
          </div>

          {/* Section 3: DNS Tunneling & Exfiltration */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2 border-b border-slate-800 pb-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              DNS Tunneling & Data Exfiltration
            </h2>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                DNS Shannon Entropy Threshold (bits)
              </label>
              <input
                type="number"
                step="0.1"
                value={config.dns_entropy_threshold}
                onChange={(e) => setConfig({ ...config, dns_entropy_threshold: parseFloat(e.target.value) })}
                className="w-full bg-slate-950 text-xs text-white border border-slate-700 rounded-lg p-2.5 font-mono focus:border-cyan-500"
              />
              <span className="text-[10px] text-slate-500">Queries exceeding this character entropy are flagged as DGA or encoded data</span>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Data Exfiltration Byte Threshold (bytes)
              </label>
              <input
                type="number"
                step="500000"
                value={config.exfiltration_bytes_threshold}
                onChange={(e) => setConfig({ ...config, exfiltration_bytes_threshold: parseInt(e.target.value) })}
                className="w-full bg-slate-950 text-xs text-white border border-slate-700 rounded-lg p-2.5 font-mono focus:border-cyan-500"
              />
              <span className="text-[10px] text-slate-500">Cumulative outbound bytes transferred indicating volumetric data exfiltration</span>
            </div>
          </div>

          {/* Section 4: Engine Simulation & Passive Guarantees */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2 border-b border-slate-800 pb-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Simulation & Operational Guarantees
            </h2>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Simulation Batch Interval (seconds)
              </label>
              <input
                type="number"
                step="0.1"
                min="0.1"
                max="5.0"
                value={config.stream_interval}
                onChange={(e) => setConfig({ ...config, stream_interval: parseFloat(e.target.value) })}
                className="w-full bg-slate-950 text-xs text-white border border-slate-700 rounded-lg p-2.5 font-mono focus:border-cyan-500"
              />
              <span className="text-[10px] text-slate-500">Base sleep duration between streaming batch emissions</span>
            </div>

            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-2 text-xs font-mono">
              <div className="flex justify-between text-slate-400">
                <span>PASSIVE_MODE:</span>
                <span className="text-emerald-400 font-bold">ENABLED (LOCKED)</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>READ_ONLY_MONITORING:</span>
                <span className="text-emerald-400 font-bold">TRUE</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>ACTIVE_RESPONSE:</span>
                <span className="text-rose-400 font-bold">DISABLED BY DESIGN</span>
              </div>
            </div>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            className="flex items-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs px-6 py-2.5 rounded-lg shadow-lg shadow-cyan-500/20 active:scale-95 transition-all cursor-pointer"
          >
            <Save className="w-4 h-4" />
            SAVE SENSITIVITY SETTINGS
          </button>
        </div>
      </form>
    </div>
  )
}
