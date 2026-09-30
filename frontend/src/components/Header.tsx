import React, { useState } from "react"
import { Shield, Play, Pause, Square, Activity, Radio, FastForward, CheckCircle2, AlertOctagon, EyeOff, Award } from "lucide-react"
import { startDemoStream, pauseDemoStream, resumeDemoStream, stopDemoStream } from "../services/api"

interface HeaderProps {
  streamState: string
  streamSpeed: number
  activeScenario: string
  wsConnected: boolean
  onStreamStateChange: (state: string, scenario: string, speed: number) => void
  onOpenJudgeMode?: () => void
}

export const Header: React.FC<HeaderProps> = ({
  streamState,
  streamSpeed,
  activeScenario,
  wsConnected,
  onStreamStateChange,
  onOpenJudgeMode
}) => {
  const [scenario, setScenario] = useState(activeScenario)
  const [speed, setSpeed] = useState(streamSpeed)
  const [loading, setLoading] = useState(false)

  const handleStart = async () => {
    setLoading(true)
    try {
      await startDemoStream(scenario, speed)
      onStreamStateChange("RUNNING", scenario, speed)
    } finally {
      setLoading(false)
    }
  }

  const handlePause = async () => {
    await pauseDemoStream()
    onStreamStateChange("PAUSED", scenario, speed)
  }

  const handleResume = async () => {
    await resumeDemoStream()
    onStreamStateChange("RUNNING", scenario, speed)
  }

  const handleStop = async () => {
    await stopDemoStream()
    onStreamStateChange("STOPPED", scenario, speed)
  }

  const handleSpeedChange = async (newSpeed: number) => {
    setSpeed(newSpeed)
    if (streamState === "RUNNING") {
      await startDemoStream(scenario, newSpeed)
      onStreamStateChange("RUNNING", scenario, newSpeed)
    }
  }

  return (
    <header className="bg-slate-950/90 backdrop-blur-md border-b border-slate-800 sticky top-0 z-50 px-6 py-3.5 shadow-2xl">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        {/* Logo and Core Guarantees Banner */}
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="w-11 h-11 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/40">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <span className="absolute -bottom-1 -right-1 flex h-3.5 w-3.5">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${wsConnected ? "bg-emerald-400" : "bg-rose-400"}`}></span>
              <span className={`relative inline-flex rounded-full h-3.5 w-3.5 ${wsConnected ? "bg-emerald-500" : "bg-rose-500"}`}></span>
            </span>
          </div>

          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-extrabold tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                UniGuard <span className="text-cyan-400 font-mono">AI</span>
              </h1>
              <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800 text-cyan-300">
                SIH26145
              </span>
            </div>
            <p className="text-xs text-slate-400 font-medium">
              Passive Unidirectional Cyber Threat Detection
            </p>
          </div>

          {/* Four Mandatory Passive Compliance Badges */}
          <div className="hidden xl:flex items-center gap-2 pl-4 border-l border-slate-800">
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-950/50 border border-emerald-800/60 text-emerald-400 text-[11px] font-bold tracking-wide">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              PASSIVE MODE
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-sky-950/50 border border-sky-800/60 text-sky-400 text-[11px] font-bold tracking-wide">
              <CheckCircle2 className="w-3.5 h-3.5 text-sky-400" />
              READ-ONLY
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-950/50 border border-amber-800/60 text-amber-400 text-[11px] font-bold tracking-wide">
              <AlertOctagon className="w-3.5 h-3.5 text-amber-400" />
              NO ACTIVE RESPONSE
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-purple-950/50 border border-purple-800/60 text-purple-400 text-[11px] font-bold tracking-wide">
              <EyeOff className="w-3.5 h-3.5 text-purple-400" />
              NO PAYLOAD DECRYPTION
            </div>
          </div>
        </div>

        {/* Action Controls & Judge Mode */}
        <div className="flex flex-wrap items-center gap-3">
          {onOpenJudgeMode && (
            <button
              onClick={onOpenJudgeMode}
              className="flex items-center gap-2 bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-400 hover:to-yellow-400 text-slate-950 font-extrabold text-xs px-3.5 py-2 rounded-xl shadow-lg shadow-amber-500/20 active:scale-95 transition-all cursor-pointer"
            >
              <Award className="w-4 h-4 fill-current" />
              JUDGE MODE
            </button>
          )}
        </div>

        {/* Live Streaming Control Bar */}
        <div className="flex flex-wrap items-center gap-3 bg-slate-900/90 border border-slate-800 rounded-xl p-1.5 shadow-inner">
          {/* Scenario Selector */}
          <div className="flex items-center gap-2 px-2">
            <Radio className="w-3.5 h-3.5 text-cyan-400" />
            <select
              value={scenario}
              onChange={(e) => setScenario(e.target.value)}
              disabled={streamState === "RUNNING"}
              className="bg-slate-950 text-xs font-medium text-slate-200 border border-slate-700 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 disabled:opacity-60 cursor-pointer"
            >
              <option value="combined_demo">Combined Attack Wave (Demo)</option>
              <option value="ddos">DDoS SYN Flood Campaign</option>
              <option value="port_scan">Reconnaissance Port Sweeps</option>
              <option value="botnet">Botnet C2 Heartbeat Beaconing</option>
              <option value="dns_tunneling">DGA / DNS Tunneling Exfiltration</option>
              <option value="encrypted_traffic">Suspicious Encrypted Bursts</option>
              <option value="exfiltration">Massive Data Exfiltration</option>
              <option value="normal">Normal Baseline Traffic</option>
            </select>
          </div>

          {/* Speed Selector */}
          <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-lg p-0.5">
            {[0.5, 1, 2, 5, 10].map((s) => (
              <button
                key={s}
                onClick={() => handleSpeedChange(s)}
                className={`px-2 py-1 text-[11px] font-mono font-semibold rounded ${
                  speed === s
                    ? "bg-cyan-500 text-slate-950 shadow"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
                } transition-all`}
              >
                {s}x
              </button>
            ))}
          </div>

          {/* Primary Action Buttons */}
          <div className="flex items-center gap-1.5">
            {streamState === "STOPPED" && (
              <button
                onClick={handleStart}
                disabled={loading}
                className="flex items-center gap-1.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs px-3.5 py-1.5 rounded-lg shadow-md shadow-cyan-500/20 active:scale-95 transition-all cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                START DEMO
              </button>
            )}

            {streamState === "RUNNING" && (
              <button
                onClick={handlePause}
                className="flex items-center gap-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 font-bold text-xs px-3 py-1.5 rounded-lg active:scale-95 transition-all cursor-pointer"
              >
                <Pause className="w-3.5 h-3.5 fill-current" />
                PAUSE
              </button>
            )}

            {streamState === "PAUSED" && (
              <button
                onClick={handleResume}
                className="flex items-center gap-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 font-bold text-xs px-3 py-1.5 rounded-lg active:scale-95 transition-all cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                RESUME
              </button>
            )}

            {streamState !== "STOPPED" && (
              <button
                onClick={handleStop}
                className="flex items-center gap-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 font-bold text-xs px-3 py-1.5 rounded-lg active:scale-95 transition-all cursor-pointer"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                STOP
              </button>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}
