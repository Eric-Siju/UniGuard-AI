import React, { useState, useEffect } from "react"
import { Briefcase, Plus, FileText, CheckCircle, Clock, AlertTriangle, User, Tag, Download } from "lucide-react"
import { Case } from "../types"
import { fetchCases, createCase, fetchCaseDetail, updateCase, exportCaseReportUrl } from "../services/api"

export const CasesPage: React.FC = () => {
  const [cases, setCases] = useState<Case[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null)
  const [caseDetail, setCaseDetail] = useState<any | null>(null)
  const [newNote, setNewNote] = useState("")

  // New Case Modal State
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [newTitle, setNewTitle] = useState("")
  const [newDesc, setNewDesc] = useState("")
  const [newSeverity, setNewSeverity] = useState("HIGH")
  const [newTags, setNewTags] = useState("SIH26145, APT-Recon")

  const loadCases = async () => {
    try {
      setLoading(true)
      const data = await fetchCases()
      setCases(data)
      if (data.length > 0 && !selectedCaseId) {
        handleSelectCase(data[0].case_id)
      }
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadCases()
  }, [])

  const handleSelectCase = async (caseId: string) => {
    try {
      setSelectedCaseId(caseId)
      const detail = await fetchCaseDetail(caseId)
      setCaseDetail(detail)
    } catch (err) {
      console.error(err)
    }
  }

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newTitle.trim()) return
    try {
      const tagsArray = newTags.split(",").map((t) => t.trim()).filter(Boolean)
      const res = await createCase({
        title: newTitle,
        description: newDesc,
        severity: newSeverity,
        tags: tagsArray,
        analyst_note: "Case initialized by security analyst."
      })
      setIsModalOpen(false)
      setNewTitle("")
      setNewDesc("")
      await loadCases()
      if (res?.case_id) {
        handleSelectCase(res.case_id)
      }
    } catch (err) {
      console.error(err)
    }
  }

  const handleAddNote = async () => {
    if (!newNote.trim() || !selectedCaseId) return
    try {
      await updateCase(selectedCaseId, { new_note: newNote })
      setNewNote("")
      handleSelectCase(selectedCaseId)
      loadCases()
    } catch (err) {
      console.error(err)
    }
  }

  const handleStatusChange = async (status: string) => {
    if (!selectedCaseId) return
    try {
      await updateCase(selectedCaseId, { status })
      handleSelectCase(selectedCaseId)
      loadCases()
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
      case "MEDIUM":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/40"
      default:
        return "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-900/60 border border-slate-800 p-5 rounded-xl">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Briefcase className="w-5 h-5 text-cyan-400" />
            SOC Case Management & Forensic Dossiers
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Inspired by Security Onion Cases. Escalate alerts, correlate assets, track analyst notes, and generate exportable incident dossiers.
          </p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg transition-colors flex items-center gap-2 cursor-pointer shadow-md shadow-cyan-500/10"
        >
          <Plus className="w-4 h-4" /> New Incident Case
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Cases List */}
        <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-slate-800 flex justify-between items-center bg-slate-950/40">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Active Cases ({cases.length})
            </span>
            <button onClick={loadCases} className="text-[11px] text-cyan-400 hover:underline">
              Refresh
            </button>
          </div>

          <div className="divide-y divide-slate-800/60 max-h-[700px] overflow-y-auto">
            {loading ? (
              <div className="p-8 text-center text-xs text-slate-500 font-mono">
                Loading SOC cases...
              </div>
            ) : cases.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 font-mono">
                No cases open. Click &quot;New Incident Case&quot; to begin.
              </div>
            ) : (
              cases.map((c) => (
                <div
                  key={c.case_id}
                  onClick={() => handleSelectCase(c.case_id)}
                  className={`p-4 cursor-pointer hover:bg-slate-800/40 transition-colors ${
                    selectedCaseId === c.case_id ? "bg-cyan-500/10 border-l-2 border-cyan-400" : ""
                  }`}
                >
                  <div className="flex justify-between items-start">
                    <span className="font-mono text-xs font-bold text-cyan-400">{c.case_id}</span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                        c.severity
                      )}`}
                    >
                      {c.severity}
                    </span>
                  </div>
                  <h4 className="text-sm font-semibold text-slate-200 mt-1 line-clamp-1">
                    {c.title}
                  </h4>
                  <div className="flex items-center gap-3 text-[11px] text-slate-400 mt-2 font-mono">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3 text-slate-500" /> {c.status}
                    </span>
                    <span>{c.related_alerts?.length || 0} alerts</span>
                    <span>{c.related_assets?.length || 0} assets</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Case Dossier Detail */}
        <div className="lg:col-span-2">
          {caseDetail ? (
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-6">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-cyan-400">
                      {caseDetail.case.case_id}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-bold border ${getSeverityBadge(
                        caseDetail.case.severity
                      )}`}
                    >
                      {caseDetail.case.severity}
                    </span>
                    <span className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                      STATUS: {caseDetail.case.status}
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-slate-100 mt-1">
                    {caseDetail.case.title}
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5 font-mono">
                    Created: {caseDetail.case.created_at} | Last Updated: {caseDetail.case.updated_at}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <a
                    href={`/api/cases/${caseDetail.case.case_id}/export`}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5"
                  >
                    <Download className="w-3.5 h-3.5" /> Export Dossier
                  </a>
                  {caseDetail.case.status !== "CLOSED" ? (
                    <button
                      onClick={() => handleStatusChange("CLOSED")}
                      className="px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/40 text-xs font-semibold rounded-lg transition-colors cursor-pointer flex items-center gap-1.5"
                    >
                      <CheckCircle className="w-3.5 h-3.5" /> Close Case
                    </button>
                  ) : (
                    <button
                      onClick={() => handleStatusChange("INVESTIGATING")}
                      className="px-3 py-1.5 bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 border border-amber-500/40 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
                    >
                      Reopen Case
                    </button>
                  )}
                </div>
              </div>

              {/* Description */}
              {caseDetail.case.description && (
                <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800 text-xs text-slate-300">
                  <span className="text-[10px] font-mono text-slate-500 block mb-1 uppercase tracking-wider">
                    Executive Summary
                  </span>
                  {caseDetail.case.description}
                </div>
              )}

              {/* Affected Assets & Tags */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-950/40 p-3.5 rounded-lg border border-slate-800">
                  <span className="text-[10px] font-mono text-slate-500 block mb-1.5 uppercase tracking-wider">
                    Observed Affected Entities
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {caseDetail.case.related_assets && caseDetail.case.related_assets.length > 0 ? (
                      caseDetail.case.related_assets.map((asset: string, i: number) => (
                        <span
                          key={i}
                          className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-cyan-950/60 text-cyan-400 border border-cyan-800/40"
                        >
                          {asset}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500">None identified.</span>
                    )}
                  </div>
                </div>

                <div className="bg-slate-950/40 p-3.5 rounded-lg border border-slate-800">
                  <span className="text-[10px] font-mono text-slate-500 block mb-1.5 uppercase tracking-wider">
                    Investigation Tags
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {caseDetail.case.tags && caseDetail.case.tags.length > 0 ? (
                      caseDetail.case.tags.map((t: string, i: number) => (
                        <span
                          key={i}
                          className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700"
                        >
                          #{t}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500">No tags.</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Attached Alerts Table */}
              <div className="space-y-2">
                <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5 uppercase tracking-wider">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  Attached Security Alerts ({caseDetail.alerts?.length || 0})
                </span>
                <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900/80 text-slate-400 font-semibold border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Alert ID</th>
                        <th className="py-2.5 px-3">Threat Class</th>
                        <th className="py-2.5 px-3">Severity</th>
                        <th className="py-2.5 px-3">Target</th>
                        <th className="py-2.5 px-3">MITRE</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                      {caseDetail.alerts && caseDetail.alerts.length > 0 ? (
                        caseDetail.alerts.map((a: any) => (
                          <tr key={a.alert_id} className="hover:bg-slate-800/40">
                            <td className="py-2 px-3 text-cyan-400 font-bold">{a.alert_id}</td>
                            <td className="py-2 px-3 text-slate-300 font-sans">{a.threat_type}</td>
                            <td className="py-2 px-3">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                                  a.severity
                                )}`}
                              >
                                {a.severity}
                              </span>
                            </td>
                            <td className="py-2 px-3 text-slate-400">
                              {a.src_ip} → {a.dst_ip}:{a.dst_port}
                            </td>
                            <td className="py-2 px-3 text-slate-400">
                              {a.mitre_technique_id ? `${a.mitre_technique_id}` : "N/A"}
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={5} className="py-4 text-center text-slate-500">
                            No alerts explicitly linked to this case yet.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Analyst Timeline & Notes */}
              <div className="space-y-3">
                <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5 uppercase tracking-wider">
                  <User className="w-4 h-4 text-cyan-400" />
                  Analyst Timeline Log
                </span>

                <div className="space-y-2">
                  {caseDetail.case.analyst_notes && caseDetail.case.analyst_notes.length > 0 ? (
                    caseDetail.case.analyst_notes.map((n: any, i: number) => (
                      <div
                        key={i}
                        className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3 text-xs space-y-1"
                      >
                        <div className="flex justify-between items-center text-[10px] font-mono text-slate-500">
                          <span className="font-bold text-slate-300">{n.author}</span>
                          <span>{n.timestamp}</span>
                        </div>
                        <p className="text-slate-300 font-sans">{n.note}</p>
                      </div>
                    ))
                  ) : (
                    <span className="text-xs text-slate-500 font-mono">No notes recorded yet.</span>
                  )}
                </div>

                {/* Add Note Input */}
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Add forensic notes or triage observation..."
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleAddNote()}
                    className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
                  />
                  <button
                    onClick={handleAddNote}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs rounded-lg transition-colors cursor-pointer"
                  >
                    Add Note
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900/20 border border-slate-800 rounded-xl p-12 text-center text-xs text-slate-500 font-mono">
              Select a case from the left panel to review its dossier and timeline.
            </div>
          )}
        </div>
      </div>

      {/* New Case Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Plus className="w-5 h-5 text-cyan-400" />
              Initialize New Incident Case
            </h3>

            <form onSubmit={handleCreateCase} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Case Title *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Multi-stage C2 and Reconnaissance Sequence"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Severity
                </label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Incident Description
                </label>
                <textarea
                  rows={3}
                  placeholder="Details of observed unidirectional anomalies, target subnets, or forensic hypotheses..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Tags (comma separated)
                </label>
                <input
                  type="text"
                  placeholder="SIH26145, APT, Recon, DNS"
                  value={newTags}
                  onChange={(e) => setNewTags(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg transition-colors cursor-pointer"
                >
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
