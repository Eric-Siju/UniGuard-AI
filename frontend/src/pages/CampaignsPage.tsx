import React, { useState, useEffect } from "react"
import { Layers, ShieldAlert, AlertTriangle, ArrowRight, Clock, Target, CheckCircle2 } from "lucide-react"
import { AttackCampaign } from "../types"
import { fetchCampaigns } from "../services/api"

interface CampaignsPageProps {
  onSelectAlert?: (alertId: string) => void
  onSelectAsset?: (ip: string) => void
}

export const CampaignsPage: React.FC<CampaignsPageProps> = ({ onSelectAlert, onSelectAsset }) => {
  const [campaigns, setCampaigns] = useState<AttackCampaign[]>([])
  const [loading, setLoading] = useState(true)

  const loadCampaigns = async () => {
    try {
      setLoading(true)
      const res = await fetchCampaigns()
      setCampaigns(res.campaigns)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadCampaigns()
  }, [])

  return (
    <div className="p-6 space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl">
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Layers className="w-5 h-5 text-cyan-400" />
          Attack Campaign Correlation & Intrusion Progressions
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Correlates separate alerts from the same source entity into an organized attack sequence story (e.g., Reconnaissance → C2 → DNS Tunneling → Exfiltration).
          Shows multi-phase progressions across time without assuming bidirectional confirmation.
        </p>
      </div>

      {loading ? (
        <div className="p-12 text-center text-xs text-slate-500 font-mono">
          Correlating multi-phase attack campaigns...
        </div>
      ) : campaigns.length === 0 ? (
        <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-12 text-center space-y-2">
          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
          <h3 className="text-sm font-bold text-slate-200">No Multi-Stage Campaigns Correlated Yet</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Campaigns formulate automatically when an observed entity exhibits 2 or more distinct threat classes (e.g. during Combined Attack Campaign scenario).
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {campaigns.map((camp) => (
            <div
              key={camp.campaign_id}
              className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-5"
            >
              {/* Campaign Header */}
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-cyan-400">
                      {camp.campaign_id}
                    </span>
                    <span className="px-2 py-0.5 rounded text-xs font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40">
                      RISK: {camp.campaign_risk}/100 CRITICAL
                    </span>
                    <span className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700 font-mono">
                      {camp.status}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-slate-100 mt-1">{camp.title}</h3>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Source Entity: <strong className="text-slate-200">{camp.entity_ip}</strong> |
                    Stages: <strong className="text-cyan-400">{camp.distinct_stages}</strong> |
                    Total Alerts: {camp.threat_count}
                  </p>
                </div>

                {onSelectAsset && (
                  <button
                    onClick={() => onSelectAsset(camp.entity_ip)}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
                  >
                    Inspect Asset {camp.entity_ip}
                  </button>
                )}
              </div>

              {/* Progressions Sequence Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {camp.phases.map((phase, idx) => (
                  <div
                    key={idx}
                    className="bg-slate-950/80 border border-slate-800 rounded-lg p-3.5 space-y-1 relative"
                  >
                    <span className="text-[10px] font-mono font-bold text-cyan-400 block uppercase tracking-wider">
                      {phase.phase_name}
                    </span>
                    <span className="text-xs font-bold text-slate-200 block">{phase.threat_type}</span>
                    <span className="text-[11px] text-slate-400 block">{phase.tactic}</span>
                    <p className="text-[11px] text-slate-500 leading-tight pt-1">
                      {phase.description}
                    </p>
                  </div>
                ))}
              </div>

              {/* Timeline of Correlated Events */}
              <div className="space-y-2">
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wider block">
                  Observed Intrusion Timeline
                </span>
                <div className="bg-slate-950 rounded-lg border border-slate-800 divide-y divide-slate-900 font-mono text-[11px]">
                  {camp.timeline.map((evt, i) => (
                    <div
                      key={i}
                      className="p-3 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 hover:bg-slate-900/40"
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-slate-500">{evt.timestamp.substring(11, 19)}</span>
                        <span className="font-bold text-rose-400">{evt.threat_type}</span>
                        <span className="text-slate-400">Target: {evt.target}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-slate-500">{evt.evidence[0] || ""}</span>
                        {onSelectAlert && (
                          <button
                            onClick={() => onSelectAlert(evt.alert_id)}
                            className="text-cyan-400 hover:text-cyan-300 text-xs font-sans font-semibold cursor-pointer"
                          >
                            View Alert →
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-cyan-950/20 border border-cyan-900/30 rounded-lg p-3 text-xs text-cyan-300">
                <strong>Recommended Analyst Prioritization:</strong> {camp.recommended_action}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
