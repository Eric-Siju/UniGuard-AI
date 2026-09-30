import React, { useState, useEffect } from "react"
import {
  Network,
  Search,
  Filter,
  ArrowUpDown,
  Upload,
  RefreshCw,
  FileSpreadsheet,
  FileCode,
  CheckCircle2,
  AlertTriangle
} from "lucide-react"
import { FlowRecord } from "../types"
import { fetchFlows, uploadDataset } from "../services/api"

export const TrafficAnalysisPage: React.FC = () => {
  const [flows, setFlows] = useState<FlowRecord[]>([])
  const [total, setTotal] = useState<number>(0)
  const [loading, setLoading] = useState<boolean>(true)
  const [search, setSearch] = useState<string>("")
  const [protocolFilter, setProtocolFilter] = useState<string>("All")
  const [threatFilter, setThreatFilter] = useState<string>("All")
  const [offset, setOffset] = useState<number>(0)
  const limit = 25

  // Upload modal state
  const [uploadOpen, setUploadOpen] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadResult, setUploadResult] = useState<any>(null)
  const [uploadError, setUploadError] = useState<string | null>(null)

  const loadFlows = () => {
    setLoading(true)
    fetchFlows({
      search: search || undefined,
      protocol: protocolFilter,
      threat_label: threatFilter,
      limit,
      offset
    })
      .then((data) => {
        setFlows(data.items)
        setTotal(data.total)
      })
      .catch((err) => console.error("Error loading flows:", err))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadFlows()
  }, [protocolFilter, threatFilter, offset])

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setOffset(0)
    loadFlows()
  }

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>, type: "csv" | "pcap") => {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    setUploadError(null)
    setUploadResult(null)
    try {
      const res = await uploadDataset(file, type)
      setUploadResult(res)
      loadFlows()
    } catch (err: any) {
      setUploadError(err.message || "Upload failed")
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="space-y-6 p-6">
      {/* Top Banner and Upload Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
        <div>
          <h1 className="text-base font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            Passive Flow Inspection & Traffic Analysis
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Query and filter unidirectional IP sessions across protocols, ports, and threat classes
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setUploadOpen(!uploadOpen)}
            className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold px-3.5 py-2 rounded-lg border border-slate-700 transition-all cursor-pointer"
          >
            <Upload className="w-4 h-4 text-cyan-400" />
            Upload PCAP / CSV
          </button>
          <button
            onClick={loadFlows}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
            title="Refresh Flows"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Upload Drawer / Modal */}
      {uploadOpen && (
        <div className="bg-slate-900/90 border border-cyan-500/30 rounded-2xl p-6 shadow-2xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Upload className="w-4 h-4 text-cyan-400" />
              Upload Offline Dataset or Packet Capture
            </h2>
            <button
              onClick={() => setUploadOpen(false)}
              className="text-xs text-slate-400 hover:text-white"
            >
              Close
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* CSV Dropzone */}
            <div className="border-2 border-dashed border-slate-800 hover:border-cyan-500/50 rounded-xl p-5 text-center bg-slate-950/60 transition-colors">
              <FileSpreadsheet className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
              <div className="text-xs font-bold text-white">Upload Flow CSV</div>
              <p className="text-[11px] text-slate-400 mt-1 mb-3">
                Auto-normalizes column schemas (src_ip, dst_ip, ports, bytes, pkts)
              </p>
              <label className="inline-block bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs px-3.5 py-1.5 rounded-lg cursor-pointer transition-all">
                Select CSV File
                <input
                  type="file"
                  accept=".csv"
                  className="hidden"
                  onChange={(e) => handleFileUpload(e, "csv")}
                />
              </label>
            </div>

            {/* PCAP Dropzone */}
            <div className="border-2 border-dashed border-slate-800 hover:border-blue-500/50 rounded-xl p-5 text-center bg-slate-950/60 transition-colors">
              <FileCode className="w-8 h-8 text-blue-400 mx-auto mb-2" />
              <div className="text-xs font-bold text-white">Upload PCAP / PCAPNG</div>
              <p className="text-[11px] text-slate-400 mt-1 mb-3">
                Passive Scapy dissection without decryption or network response
              </p>
              <label className="inline-block bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs px-3.5 py-1.5 rounded-lg cursor-pointer transition-all">
                Select PCAP File
                <input
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  className="hidden"
                  onChange={(e) => handleFileUpload(e, "pcap")}
                />
              </label>
            </div>
          </div>

          {uploading && (
            <div className="text-center text-xs font-mono text-cyan-400 animate-pulse">
              Parsing packets and aggregating flows...
            </div>
          )}

          {uploadResult && (
            <div className="p-3 bg-emerald-950/50 border border-emerald-800 rounded-lg text-xs text-emerald-300 flex items-center gap-2 font-mono">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>Parsed {uploadResult.flows_parsed || uploadResult.flows_aggregated} flows successfully from {uploadResult.filename}!</span>
            </div>
          )}

          {uploadError && (
            <div className="p-3 bg-rose-950/50 border border-rose-800 rounded-lg text-xs text-rose-300 flex items-center gap-2 font-mono">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{uploadError}</span>
            </div>
          )}
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex items-center gap-2 flex-1 min-w-[260px]">
          <div className="relative w-full">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search by IP, Port, or Flow ID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 text-xs text-slate-200 pl-9 pr-4 py-2 rounded-lg border border-slate-700 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
          <button
            type="submit"
            className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs px-3.5 py-2 rounded-lg cursor-pointer"
          >
            Search
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-3">
          {/* Protocol Filter */}
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5 text-cyan-400" />
            <span>Proto:</span>
            <select
              value={protocolFilter}
              onChange={(e) => {
                setProtocolFilter(e.target.value)
                setOffset(0)
              }}
              className="bg-slate-950 text-xs text-slate-200 border border-slate-700 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              <option value="All">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="DNS">DNS</option>
              <option value="TLS">TLS</option>
              <option value="ICMP">ICMP</option>
            </select>
          </div>

          {/* Threat Class Filter */}
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>Threat:</span>
            <select
              value={threatFilter}
              onChange={(e) => {
                setThreatFilter(e.target.value)
                setOffset(0)
              }}
              className="bg-slate-950 text-xs text-slate-200 border border-slate-700 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              <option value="All">All Classes</option>
              <option value="Normal">Normal</option>
              <option value="DDoS">DDoS</option>
              <option value="Port Scan">Port Scan</option>
              <option value="Botnet C2">Botnet C2</option>
              <option value="DGA / DNS Tunneling">DGA / DNS Tunneling</option>
              <option value="Suspicious Encrypted Traffic">Suspicious Encrypted</option>
              <option value="Data Exfiltration">Data Exfiltration</option>
            </select>
          </div>
        </div>
      </div>

      {/* Flows Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <div className="text-xs text-slate-400 font-mono">
            Showing {flows.length} of {total} records
          </div>
          <div className="flex items-center gap-2">
            <button
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - limit))}
              className="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded font-semibold cursor-pointer"
            >
              Previous
            </button>
            <span className="text-xs text-slate-400 font-mono">
              Page {Math.floor(offset / limit) + 1}
            </span>
            <button
              disabled={offset + limit >= total}
              onClick={() => setOffset(offset + limit)}
              className="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded font-semibold cursor-pointer"
            >
              Next
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-semibold">
                <th className="py-2.5 px-3">Flow Reference</th>
                <th className="py-2.5 px-3">Endpoints</th>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Duration</th>
                <th className="py-2.5 px-3">Volume</th>
                <th className="py-2.5 px-3">Velocity</th>
                <th className="py-2.5 px-3">DNS / SNI</th>
                <th className="py-2.5 px-3 text-right">Classification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {flows.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    No flows match current search criteria.
                  </td>
                </tr>
              ) : (
                flows.map((f, i) => (
                  <tr key={i} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-3 text-slate-400 truncate max-w-[130px]">{f.flow_id}</td>
                    <td className="py-2.5 px-3 text-slate-200">
                      {f.src_ip}:{f.src_port} &rarr; {f.dst_ip}:{f.dst_port}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-cyan-300 font-bold border border-slate-700">
                        {f.protocol}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">{f.duration.toFixed(2)}s</td>
                    <td className="py-2.5 px-3 text-slate-300">
                      {f.total_bytes >= 1024 * 1024
                        ? `${(f.total_bytes / (1024 * 1024)).toFixed(1)}MB`
                        : `${(f.total_bytes / 1024).toFixed(1)}KB`}{" "}
                      ({f.total_packets}p)
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">
                      {f.packets_per_sec.toFixed(0)} pps
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 max-w-[140px] truncate">
                      {f.dns_query || f.sni || "-"}
                    </td>
                    <td className="py-2.5 px-3 text-right font-sans">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          f.threat_label === "Normal"
                            ? "bg-slate-800 text-slate-400"
                            : "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                        }`}
                      >
                        {f.threat_label}
                      </span>
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
