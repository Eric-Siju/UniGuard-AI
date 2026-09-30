import React, { useState, useEffect } from "react"
import { ShieldCheck, Plus, Database, Lock, AlertCircle, RefreshCw } from "lucide-react"
import { ThreatIntelIndicator } from "../types"
import { fetchThreatIntel, addThreatIntel } from "../services/api"

export const ThreatIntelPage: React.FC = () => {
  const [indicators, setIndicators] = useState<ThreatIntelIndicator[]>([])
  const [loading, setLoading] = useState(true)

  // Form State
  const [type, setType] = useState("IP")
  const [indicator, setIndicator] = useState("")
  const [desc, setDesc] = useState("")
  const [source, setSource] = useState("Local CERT Advisory")
  const [severity, setSeverity] = useState("HIGH")
  const [formMsg, setFormMsg] = useState("")

  const loadIntel = async () => {
    try {
      setLoading(true)
      const res = await fetchThreatIntel()
      setIndicators(res.indicators)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadIntel()
  }, [])

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!indicator.trim()) return
    try {
      await addThreatIntel({
        indicator_type: type,
        indicator: indicator.trim(),
        description: desc,
        source: source,
        severity: severity
      })
      setIndicator("")
      setDesc("")
      setFormMsg("Indicator added to offline local store.")
      setTimeout(() => setFormMsg(""), 3000)
      loadIntel()
    } catch (err) {
      console.error(err)
    }
  }

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-rose-500/20 text-rose-400 border-rose-500/40"
      case "HIGH":
        return "bg-amber-500/20 text-amber-400 border-amber-500/40"
      default:
        return "bg-cyan-500/20 text-cyan-400 border-cyan-500/40"
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-900/60 border border-slate-800 p-5 rounded-xl">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            Local Threat Intelligence (Offline-First)
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Offline indicator matching without external egress calls. Passive matching against IP, DNS query domains, and TLS SNIs.
          </p>
        </div>
        <div className="flex items-center gap-2 bg-emerald-950/60 border border-emerald-800/40 px-3 py-1.5 rounded-lg text-xs font-mono text-emerald-400">
          <Lock className="w-3.5 h-3.5" /> ZERO OUTBOUND CALLS ENFORCED
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Indicators Table */}
        <div className="lg:col-span-2 bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-slate-800 flex justify-between items-center bg-slate-950/40">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Enrolled Offline Indicators ({indicators.length})
            </span>
            <button
              onClick={loadIntel}
              className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
            >
              <RefreshCw className="w-3 h-3" /> Refresh
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 font-semibold border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Indicator</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Source</th>
                  <th className="py-3 px-4">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {loading ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500 font-mono">
                      Loading offline threat intelligence...
                    </td>
                  </tr>
                ) : indicators.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500 font-mono">
                      No indicators currently enrolled.
                    </td>
                  </tr>
                ) : (
                  indicators.map((ind, i) => (
                    <tr key={i} className="hover:bg-slate-800/40">
                      <td className="py-3 px-4">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                          {ind.indicator_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono font-bold text-slate-200">
                        {ind.indicator}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                            ind.severity
                          )}`}
                        >
                          {ind.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">{ind.source}</td>
                      <td className="py-3 px-4 text-slate-300 text-xs">{ind.description}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Add Indicator Card */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <Plus className="w-4 h-4 text-cyan-400" />
            Add Local Offline Indicator
          </h3>

          <form onSubmit={handleAdd} className="space-y-3.5">
            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">
                Indicator Type
              </label>
              <select
                value={type}
                onChange={(e) => setType(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
              >
                <option value="IP">IP Address</option>
                <option value="DOMAIN">Domain Name (DNS)</option>
                <option value="SNI">TLS Server Name (SNI)</option>
              </select>
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">
                Indicator Value *
              </label>
              <input
                type="text"
                required
                placeholder="e.g. 10.0.0.99 or bad-domain.internal"
                value={indicator}
                onChange={(e) => setIndicator(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50 font-mono"
              />
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">Severity</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
              </select>
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">Source Feed</label>
              <input
                type="text"
                value={source}
                onChange={(e) => setSource(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
              />
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">Description</label>
              <input
                type="text"
                placeholder="e.g. APT-29 C2 Infrastructure Node"
                value={desc}
                onChange={(e) => setDesc(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
              />
            </div>

            <button
              type="submit"
              className="w-full py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg transition-colors cursor-pointer"
            >
              Enroll Offline Indicator
            </button>

            {formMsg && (
              <p className="text-xs text-emerald-400 font-mono text-center">{formMsg}</p>
            )}
          </form>
        </div>
      </div>
    </div>
  )
}
