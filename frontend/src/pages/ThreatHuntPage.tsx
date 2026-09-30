import React, { useState, useEffect } from "react"
import { Search, Filter, ShieldAlert, ArrowRight, Database, ExternalLink, RefreshCw } from "lucide-react"
import { executeThreatHunt } from "../services/api"

interface ThreatHuntPageProps {
  initialSearchIp?: string
  onSelectAlert?: (alertId: string) => void
  onSelectAsset?: (ip: string) => void
}

export const ThreatHuntPage: React.FC<ThreatHuntPageProps> = ({
  initialSearchIp = "",
  onSelectAlert,
  onSelectAsset
}) => {
  const [srcIp, setSrcIp] = useState(initialSearchIp)
  const [dstIp, setDstIp] = useState("")
  const [protocol, setProtocol] = useState("All")
  const [threatType, setThreatType] = useState("All")
  const [items, setItems] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)

  const runHunt = async () => {
    try {
      setLoading(true)
      const res = await executeThreatHunt({
        src_ip: srcIp || undefined,
        dst_ip: dstIp || undefined,
        protocol: protocol !== "All" ? protocol : undefined,
        threat_type: threatType !== "All" ? threatType : undefined,
        limit: 50
      })
      setItems(res.items)
      setTotal(res.total)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    runHunt()
  }, [])

  return (
    <div className="p-6 space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl">
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Search className="w-5 h-5 text-cyan-400" />
          Passive Threat Hunting Console
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Hypothesis-driven threat hunting over passively captured unidirectional telemetry.
          Filter structured flow metadata and pivot seamlessly to related alerts and entity assets. Zero active scans or network probes.
        </p>
      </div>

      {/* Query Filter Console */}
      <div className="bg-slate-900/40 border border-slate-800 p-4 rounded-xl space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <label className="text-[11px] font-mono text-slate-400 block mb-1 uppercase tracking-wider">
              Source IP
            </label>
            <input
              type="text"
              placeholder="e.g. 192.168.1.10"
              value={srcIp}
              onChange={(e) => setSrcIp(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50 font-mono"
            />
          </div>

          <div>
            <label className="text-[11px] font-mono text-slate-400 block mb-1 uppercase tracking-wider">
              Destination IP
            </label>
            <input
              type="text"
              placeholder="e.g. 10.0.0.99"
              value={dstIp}
              onChange={(e) => setDstIp(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50 font-mono"
            />
          </div>

          <div>
            <label className="text-[11px] font-mono text-slate-400 block mb-1 uppercase tracking-wider">
              Protocol
            </label>
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
            >
              <option value="All">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="DNS">DNS</option>
              <option value="TLS">TLS</option>
              <option value="ICMP">ICMP</option>
            </select>
          </div>

          <div>
            <label className="text-[11px] font-mono text-slate-400 block mb-1 uppercase tracking-wider">
              Threat Category
            </label>
            <select
              value={threatType}
              onChange={(e) => setThreatType(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
            >
              <option value="All">All Categories</option>
              <option value="Port Scan">Port Scan</option>
              <option value="Botnet C2">Botnet C2</option>
              <option value="DGA / DNS Tunneling">DGA / DNS Tunneling</option>
              <option value="DDoS">DDoS</option>
              <option value="Suspicious Encrypted">Suspicious Encrypted</option>
              <option value="Data Exfiltration">Data Exfiltration</option>
              <option value="Normal">Normal Traffic</option>
            </select>
          </div>
        </div>

        <div className="flex justify-between items-center pt-1 border-t border-slate-800/80">
          <span className="text-xs text-slate-400 font-mono">
            Showing <strong className="text-cyan-400">{items.length}</strong> of{" "}
            <strong className="text-slate-200">{total}</strong> matched records
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => {
                setSrcIp("")
                setDstIp("")
                setProtocol("All")
                setThreatType("All")
              }}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
            >
              Clear Filters
            </button>
            <button
              onClick={runHunt}
              className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Execute Hunt
            </button>
          </div>
        </div>
      </div>

      {/* Hunt Results Table */}
      <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Destination IP:Port</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">Bytes / Packets</th>
                <th className="py-3 px-4">Threat Label</th>
                <th className="py-3 px-4 text-right">Pivots</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    Executing threat hunt query...
                  </td>
                </tr>
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No flow records match query criteria.
                  </td>
                </tr>
              ) : (
                items.map((row) => (
                  <tr key={row.flow_id} className="hover:bg-slate-800/40">
                    <td className="py-3 px-4 text-slate-400">
                      {row.timestamp ? row.timestamp.replace("T", " ").substring(0, 19) : "N/A"}
                    </td>
                    <td className="py-3 px-4 text-slate-200 font-bold">{row.src_ip}</td>
                    <td className="py-3 px-4 text-slate-300">
                      {row.dst_ip}:{row.dst_port}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                        {row.protocol}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {row.total_bytes} B / {row.total_packets} pkts
                    </td>
                    <td className="py-3 px-4 font-sans">
                      {row.threat_label !== "Normal" ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40">
                          {row.threat_label}
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[10px]">Normal</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2 font-sans">
                      {onSelectAsset && (
                        <button
                          onClick={() => onSelectAsset(row.src_ip)}
                          className="text-[11px] text-cyan-400 hover:text-cyan-300 font-semibold cursor-pointer"
                        >
                          Asset
                        </button>
                      )}
                      {row.pivot_alert && onSelectAlert && (
                        <button
                          onClick={() => onSelectAlert(row.pivot_alert.alert_id)}
                          className="text-[11px] text-amber-400 hover:text-amber-300 font-semibold cursor-pointer"
                        >
                          Alert →
                        </button>
                      )}
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
