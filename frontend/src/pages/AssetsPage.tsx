import React, { useState, useEffect } from "react"
import { ShieldAlert, Server, Laptop, Globe, ArrowRight, Activity, Search, ExternalLink, Network } from "lucide-react"
import { Asset } from "../types"
import { fetchAssets, fetchAssetDetail } from "../services/api"

interface AssetsPageProps {
  onNavigateToHunt?: (ip: string) => void
}

export const AssetsPage: React.FC<AssetsPageProps> = ({ onNavigateToHunt }) => {
  const [assets, setAssets] = useState<Asset[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState("")
  const [selectedAsset, setSelectedAsset] = useState<any | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  const loadAssets = async () => {
    try {
      setLoading(true)
      const res = await fetchAssets()
      setAssets(res.assets)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAssets()
  }, [])

  const handleSelectAsset = async (ip: string) => {
    try {
      setDetailLoading(true)
      const detail = await fetchAssetDetail(ip)
      setSelectedAsset(detail)
    } catch (err) {
      console.error(err)
    } finally {
      setDetailLoading(false)
    }
  }

  const filteredAssets = assets.filter((a) =>
    a.ip.toLowerCase().includes(search.toLowerCase()) ||
    a.role.toLowerCase().includes(search.toLowerCase())
  )

  const getRiskBadge = (level: string) => {
    switch (level) {
      case "CRITICAL":
        return "bg-rose-500/20 text-rose-400 border-rose-500/40"
      case "HIGH":
        return "bg-amber-500/20 text-amber-400 border-amber-500/40"
      case "MEDIUM":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/40"
      default:
        return "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-900/60 border border-slate-800 p-5 rounded-xl">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" />
            Passive Asset Inventory & Entity Risk
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Entities derived exclusively from observed unidirectional traffic without active scanning.
            Transparent 0–100 risk scoring based on alert severity, baseline deviations, and offline threat intel.
          </p>
        </div>
        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="relative flex-1 md:w-64">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search IP or role..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50 font-mono"
            />
          </div>
          <button
            onClick={loadAssets}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Assets Table */}
        <div className={`space-y-4 ${selectedAsset ? "lg:col-span-2" : "lg:col-span-3"}`}>
          <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-5 py-3 border-b border-slate-800 flex justify-between items-center bg-slate-950/40">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Observed Entities ({filteredAssets.length})
              </span>
              <span className="text-[11px] text-slate-500 font-mono">
                Click entity to inspect explainable risk factors & communication map
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Entity IP</th>
                    <th className="py-3 px-4">Inferred Role</th>
                    <th className="py-3 px-4">Flows</th>
                    <th className="py-3 px-4">Bytes Out</th>
                    <th className="py-3 px-4">Threats</th>
                    <th className="py-3 px-4">Entity Risk</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {loading ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-500 font-mono">
                        Loading observed entity assets...
                      </td>
                    </tr>
                  ) : filteredAssets.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-500 font-mono">
                        No observed assets match query.
                      </td>
                    </tr>
                  ) : (
                    filteredAssets.map((asset) => (
                      <tr
                        key={asset.ip}
                        onClick={() => handleSelectAsset(asset.ip)}
                        className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${
                          selectedAsset?.ip === asset.ip ? "bg-cyan-500/10" : ""
                        }`}
                      >
                        <td className="py-3 px-4 font-mono font-bold text-slate-200">
                          {asset.ip}
                        </td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                            {asset.role}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400">
                          {asset.flows_count.toLocaleString()}
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400">
                          {(asset.bytes_out / 1024).toFixed(1)} KB
                        </td>
                        <td className="py-3 px-4">
                          {asset.threat_count > 0 ? (
                            <span className="font-mono text-rose-400 font-bold">
                              {asset.threat_count} alerts
                            </span>
                          ) : (
                            <span className="text-slate-500">0</span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getRiskBadge(
                                asset.risk_level
                              )}`}
                            >
                              {asset.risk_score}/100 {asset.risk_level}
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              handleSelectAsset(asset.ip)
                            }}
                            className="text-cyan-400 hover:text-cyan-300 font-semibold text-xs inline-flex items-center gap-1"
                          >
                            Inspect <ArrowRight className="w-3.5 h-3.5" />
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

        {/* Selected Asset Inspection & Communication Map */}
        {selectedAsset && (
          <div className="space-y-4">
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-5">
              <div className="flex justify-between items-start border-b border-slate-800 pb-3">
                <div>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                    Inspecting Entity
                  </span>
                  <h3 className="text-lg font-bold font-mono text-cyan-400">{selectedAsset.ip}</h3>
                </div>
                <button
                  onClick={() => setSelectedAsset(null)}
                  className="text-slate-500 hover:text-slate-300 text-xs font-mono"
                >
                  ✕ Close
                </button>
              </div>

              {/* Explainable Risk Breakdown */}
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-xs font-bold text-slate-300">Explainable Risk Score</span>
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-bold border ${getRiskBadge(
                      selectedAsset.risk_level
                    )}`}
                  >
                    {selectedAsset.risk_score} / 100 ({selectedAsset.risk_level})
                  </span>
                </div>

                <div className="bg-slate-950/80 rounded-lg p-3 border border-slate-800 space-y-2">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                    Mathematical Risk Contributors:
                  </span>
                  {selectedAsset.risk_factors && selectedAsset.risk_factors.length > 0 ? (
                    selectedAsset.risk_factors.map((rf: any, i: number) => (
                      <div key={i} className="flex justify-between items-center text-xs border-b border-slate-900 pb-1">
                        <span className="text-slate-300">{rf.factor}</span>
                        <span className="font-mono font-bold text-rose-400">+{rf.points} pts</span>
                      </div>
                    ))
                  ) : (
                    <span className="text-xs text-slate-500 font-mono">
                      No malicious risk contributors observed. Entity operating in benign baseline.
                    </span>
                  )}
                </div>
              </div>

              {/* Passive Communications Map */}
              <div className="space-y-2">
                <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <Network className="w-4 h-4 text-cyan-400" />
                  Observed Communications ({selectedAsset.communications?.length || 0})
                </span>
                <div className="bg-slate-950 rounded-lg p-3 border border-slate-800 max-h-48 overflow-y-auto space-y-2 font-mono text-[11px]">
                  {selectedAsset.communications && selectedAsset.communications.length > 0 ? (
                    selectedAsset.communications.map((c: any, i: number) => (
                      <div key={i} className="flex justify-between items-center text-slate-400 border-b border-slate-900 pb-1">
                        <span className="text-slate-300">{c.peer_ip}</span>
                        <span>Ports: {c.ports?.join(", ") || "N/A"}</span>
                        <span>{c.flows} flows</span>
                      </div>
                    ))
                  ) : (
                    <span className="text-slate-500">No multi-hop peers recorded.</span>
                  )}
                </div>
              </div>

              {/* Pivot Button */}
              {onNavigateToHunt && (
                <button
                  onClick={() => onNavigateToHunt(selectedAsset.ip)}
                  className="w-full py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 cursor-pointer"
                >
                  <ExternalLink className="w-4 h-4" /> Pivot to Threat Hunt for {selectedAsset.ip}
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
