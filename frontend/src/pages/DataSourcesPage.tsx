import React, { useState, useEffect } from "react"
import { Database, Upload, CheckCircle2, AlertCircle, FileCode, RefreshCw } from "lucide-react"
import { DataSourceInfo } from "../types"
import { fetchDataSources, uploadZeekJson, uploadSuricataEve } from "../services/api"

export const DataSourcesPage: React.FC = () => {
  const [sources, setSources] = useState<DataSourceInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [uploadMsg, setUploadMsg] = useState<{ text: string; error: boolean } | null>(null)
  const [isUploading, setIsUploading] = useState(false)

  const loadSources = async () => {
    try {
      setLoading(true)
      const res = await fetchDataSources()
      setSources(res.sources)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadSources()
  }, [])

  const handleZeekUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      setIsUploading(true)
      setUploadMsg({ text: `Uploading and parsing Zeek JSON log: ${file.name}...`, error: false })
      const res = await uploadZeekJson(file)
      setUploadMsg({
        text: `Successfully parsed ${res.records_parsed} Zeek flow records from ${file.name}`,
        error: false
      })
      loadSources()
    } catch (err: any) {
      setUploadMsg({ text: `Zeek parsing error: ${err.message}`, error: true })
    } finally {
      setIsUploading(false)
    }
  }

  const handleEveUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      setIsUploading(true)
      setUploadMsg({ text: `Uploading and parsing Suricata EVE JSON: ${file.name}...`, error: false })
      const res = await uploadSuricataEve(file)
      setUploadMsg({
        text: `Successfully parsed ${res.records_parsed} Suricata EVE events from ${file.name}`,
        error: false
      })
      loadSources()
    } catch (err: any) {
      setUploadMsg({ text: `Suricata EVE parsing error: ${err.message}`, error: true })
    } finally {
      setIsUploading(false)
    }
  }

  const getStatusBadge = (status: string) => {
    if (status === "ONLINE") {
      return "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
    }
    if (status === "READY") {
      return "bg-cyan-500/20 text-cyan-400 border-cyan-500/40"
    }
    if (status.startsWith("Unavailable")) {
      return "bg-slate-800 text-slate-400 border-slate-700"
    }
    return "bg-rose-500/20 text-rose-400 border-rose-500/40"
  }

  return (
    <div className="p-6 space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-900/60 border border-slate-800 p-5 rounded-xl">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400" />
            Ingestion Pipeline Health & Data Sources
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time status of multi-source NSM adapters. Supports Zeek JSON, Suricata EVE JSON, passive PCAP, and offline threat feeds.
            Statuses ground actual dependencies; no simulated online flags.
          </p>
        </div>
        <button
          onClick={loadSources}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh Telemetry
        </button>
      </div>

      {uploadMsg && (
        <div
          className={`p-3.5 rounded-lg border text-xs font-mono flex items-center gap-2 ${
            uploadMsg.error
              ? "bg-rose-950/60 border-rose-800 text-rose-300"
              : "bg-emerald-950/60 border-emerald-800 text-emerald-300"
          }`}
        >
          {uploadMsg.error ? (
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          )}
          <span>{uploadMsg.text}</span>
        </div>
      )}

      {/* Data Sources Health Table */}
      <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-800 bg-slate-950/40">
          <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
            Connected Ingestion Adapters ({sources.length})
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Adapter Source</th>
                <th className="py-3 px-4">Format / Schema</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Received</th>
                <th className="py-3 px-4">Parsed</th>
                <th className="py-3 px-4">Throughput</th>
                <th className="py-3 px-4">Last Event</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    Querying ingestion adapters...
                  </td>
                </tr>
              ) : (
                sources.map((s, i) => (
                  <tr key={i} className="hover:bg-slate-800/40">
                    <td className="py-3 px-4 font-sans font-bold text-slate-200">{s.source}</td>
                    <td className="py-3 px-4 text-slate-400 font-sans">{s.type}</td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(
                          s.status
                        )}`}
                      >
                        {s.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">{s.records_received.toLocaleString()}</td>
                    <td className="py-3 px-4 text-cyan-400 font-bold">
                      {s.records_parsed.toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-slate-400">{s.processing_rate}</td>
                    <td className="py-3 px-4 text-slate-500 text-[10px]">{s.last_event}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* External NSM Upload Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Zeek JSON Uploader */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2">
            <FileCode className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200">Upload Zeek JSON Log</h3>
          </div>
          <p className="text-xs text-slate-400">
            Ingests Zeek connection summaries (<code>conn.log</code>), DNS lookups (<code>dns.log</code>),
            or SSL handshakes (<code>ssl.log</code>) in standard JSON stream format.
          </p>
          <div className="border-2 border-dashed border-slate-800 hover:border-cyan-500/50 rounded-xl p-6 text-center cursor-pointer transition-colors bg-slate-950/40">
            <input
              type="file"
              accept=".json,.log"
              id="zeek-file"
              onChange={handleZeekUpload}
              disabled={isUploading}
              className="hidden"
            />
            <label htmlFor="zeek-file" className="cursor-pointer space-y-2 block">
              <Upload className="w-6 h-6 text-slate-500 mx-auto" />
              <span className="text-xs font-semibold text-cyan-400 block">
                Choose Zeek JSON file (.log, .json)
              </span>
              <span className="text-[11px] text-slate-500 block">Normalized passively into UniGuard flow schema</span>
            </label>
          </div>
        </div>

        {/* Suricata EVE JSON Uploader */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2">
            <FileCode className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200">Upload Suricata EVE JSON</h3>
          </div>
          <p className="text-xs text-slate-400">
            Ingests Suricata unified EVE JSON output (<code>eve.json</code>) including flow telemetry,
            external IDS alerts, DNS records, and TLS handshakes.
          </p>
          <div className="border-2 border-dashed border-slate-800 hover:border-cyan-500/50 rounded-xl p-6 text-center cursor-pointer transition-colors bg-slate-950/40">
            <input
              type="file"
              accept=".json"
              id="eve-file"
              onChange={handleEveUpload}
              disabled={isUploading}
              className="hidden"
            />
            <label htmlFor="eve-file" className="cursor-pointer space-y-2 block">
              <Upload className="w-6 h-6 text-slate-500 mx-auto" />
              <span className="text-xs font-semibold text-cyan-400 block">
                Choose Suricata EVE file (eve.json)
              </span>
              <span className="text-[11px] text-slate-500 block">Multi-event extraction without active probing</span>
            </label>
          </div>
        </div>
      </div>
    </div>
  )
}
