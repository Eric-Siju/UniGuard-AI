import React, { useState } from "react"
import { FileText, Download, Printer, RefreshCw, CheckCircle2, ShieldCheck } from "lucide-react"

export const ReportPage: React.FC = () => {
  const [reportUrl, setReportUrl] = useState<string>("/api/report?format=html")
  const [refreshKey, setRefreshKey] = useState<number>(0)

  const handleGenerate = () => {
    setRefreshKey((prev) => prev + 1)
  }

  const handleOpenNewWindow = () => {
    window.open(`/api/report?format=html&t=${Date.now()}`, "_blank")
  }

  return (
    <div className="space-y-6 p-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
        <div>
          <h1 className="text-base font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            Executive Security Audit & Compliance Report
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Generate formal documentation summarizing passive observations, threats, ML verification, and diode compliance
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleGenerate}
            className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold px-3.5 py-2.5 rounded-lg border border-slate-700 transition-all cursor-pointer"
          >
            <RefreshCw className="w-4 h-4 text-cyan-400" />
            Regenerate Report
          </button>
          <button
            onClick={handleOpenNewWindow}
            className="flex items-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs px-4 py-2.5 rounded-lg shadow-lg shadow-cyan-500/20 transition-all cursor-pointer"
          >
            <Printer className="w-4 h-4" />
            Print / Export PDF
          </button>
        </div>
      </div>

      {/* Embedded Live Report Preview Frame */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 shadow-xl space-y-3">
        <div className="flex items-center justify-between text-xs text-slate-400 border-b border-slate-800 pb-2">
          <span className="font-mono flex items-center gap-1.5 text-cyan-400">
            <ShieldCheck className="w-4 h-4" /> Live Report Preview (Rendered from /api/report)
          </span>
          <span className="font-mono text-[11px]">Print-Optimized Document</span>
        </div>

        <div className="w-full h-[750px] bg-slate-950 rounded-xl overflow-hidden border border-slate-800">
          <iframe
            key={refreshKey}
            src={`/api/report?format=html&t=${refreshKey}`}
            className="w-full h-full border-0"
            title="Security Audit Report"
          />
        </div>
      </div>
    </div>
  )
}
