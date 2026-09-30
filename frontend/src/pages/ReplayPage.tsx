import React, { useState } from "react"
import { RotateCcw, Play, Pause, Square, Film, Shield, CheckCircle, Radio } from "lucide-react"
import { startDemoStream, pauseDemoStream, resumeDemoStream, stopDemoStream } from "../services/api"

interface ReplayPageProps {
  streamState: string
  streamSpeed: number
  activeScenario: string
  flowsStreamed: number
  threatsStreamed: number
  onStateChange: (state: string, scenario: string, speed: number) => void
}

export const ReplayPage: React.FC<ReplayPageProps> = ({
  streamState,
  streamSpeed,
  activeScenario,
  flowsStreamed,
  threatsStreamed,
  onStateChange
}) => {
  const [selectedScenario, setSelectedScenario] = useState(activeScenario)
  const [speed, setSpeed] = useState(streamSpeed)

  const scenarios = [
    {
      id: "combined_demo",
      title: "Full SIH Evaluation Attack Wave",
      description: "Interleaved progression starting with normal baseline, followed by reconnaissance port scans, volumetric DDoS swarm, periodic C2 beaconing, DGA tunneling, and massive data exfiltration.",
      flows: "~1950 flows",
      color: "from-cyan-500/20 to-blue-500/20 border-cyan-500/30"
    },
    {
      id: "ddos",
      title: "Volumetric & SYN Flood Swarm",
      description: "Distributed sources targeting protected server port 80 with extreme packet velocities exceeding 400 pkts/sec and skewed SYN ratios.",
      flows: "~300 flows",
      color: "from-rose-500/20 to-red-500/20 border-rose-500/30"
    },
    {
      id: "port_scan",
      title: "Reconnaissance Port Sweeps",
      description: "Single scanner probing 40+ destination ports and multi-host subnets with brief millisecond connection attempts.",
      flows: "~300 flows",
      color: "from-amber-500/20 to-orange-500/20 border-amber-500/30"
    },
    {
      id: "botnet",
      title: "Botnet C2 Periodic Beaconing",
      description: "Compromised internal hosts transmitting synchronous heartbeats to fixed external C2 nodes with low inter-arrival jitter (<0.05s).",
      flows: "~250 flows",
      color: "from-purple-500/20 to-indigo-500/20 border-purple-500/30"
    },
    {
      id: "dns_tunneling",
      title: "DGA & DNS Tunneling Exfiltration",
      description: "High Shannon entropy subdomain lookups encoding data chunks into recursive DNS queries without touching TCP/HTTP.",
      flows: "~250 flows",
      color: "from-emerald-500/20 to-teal-500/20 border-emerald-500/30"
    },
    {
      id: "encrypted_traffic",
      title: "Suspicious Encrypted Covert Channel",
      description: "TLS traffic observed on non-standard ports with automated non-interactive transmission bursts.",
      flows: "~250 flows",
      color: "from-sky-500/20 to-cyan-500/20 border-sky-500/30"
    },
    {
      id: "exfiltration",
      title: "High-Volume Data Exfiltration",
      description: "Massive sustained outbound egress (>10MB) with extreme 40:1 outbound-to-inbound asymmetry to external drops.",
      flows: "~200 flows",
      color: "from-rose-500/20 to-purple-500/20 border-rose-500/30"
    }
  ]

  const handleStart = async (scId: string) => {
    setSelectedScenario(scId)
    await startDemoStream(scId, speed)
    onStateChange("RUNNING", scId, speed)
  }

  const handlePause = async () => {
    await pauseDemoStream()
    onStateChange("PAUSED", selectedScenario, speed)
  }

  const handleResume = async () => {
    await resumeDemoStream()
    onStateChange("RUNNING", selectedScenario, speed)
  }

  const handleStop = async () => {
    await stopDemoStream()
    onStateChange("STOPPED", selectedScenario, speed)
  }

  const handleSpeedSelect = async (s: number) => {
    setSpeed(s)
    if (streamState === "RUNNING") {
      await startDemoStream(selectedScenario, s)
      onStateChange("RUNNING", selectedScenario, s)
    }
  }

  return (
    <div className="space-y-6 p-6">
      {/* Top Replay Studio Controller */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h1 className="text-base font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Film className="w-5 h-5 text-cyan-400" />
              Traffic Replay Studio & Demonstration Controls
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Simulate live physical TAP arrival from offline network flow captures at adjustable speeds
            </p>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-slate-400">STATUS:</span>
            <span
              className={`px-2.5 py-1 rounded font-bold ${
                streamState === "RUNNING"
                  ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                  : streamState === "PAUSED"
                  ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                  : "bg-slate-800 text-slate-400 border border-slate-700"
              }`}
            >
              {streamState}
            </span>
          </div>
        </div>

        {/* Master Control Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-950/70 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center gap-3">
            {streamState === "STOPPED" && (
              <button
                onClick={() => handleStart(selectedScenario)}
                className="flex items-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-extrabold text-xs px-5 py-2.5 rounded-lg shadow-lg shadow-cyan-500/20 active:scale-95 transition-all cursor-pointer"
              >
                <Play className="w-4 h-4 fill-current" />
                PLAY REPLAY
              </button>
            )}

            {streamState === "RUNNING" && (
              <button
                onClick={handlePause}
                className="flex items-center gap-2 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 font-extrabold text-xs px-5 py-2.5 rounded-lg active:scale-95 transition-all cursor-pointer"
              >
                <Pause className="w-4 h-4 fill-current" />
                PAUSE
              </button>
            )}

            {streamState === "PAUSED" && (
              <button
                onClick={handleResume}
                className="flex items-center gap-2 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 font-extrabold text-xs px-5 py-2.5 rounded-lg active:scale-95 transition-all cursor-pointer"
              >
                <Play className="w-4 h-4 fill-current" />
                RESUME
              </button>
            )}

            {streamState !== "STOPPED" && (
              <button
                onClick={handleStop}
                className="flex items-center gap-2 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 font-extrabold text-xs px-5 py-2.5 rounded-lg active:scale-95 transition-all cursor-pointer"
              >
                <Square className="w-4 h-4 fill-current" />
                STOP
              </button>
            )}
          </div>

          {/* Speed Selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">REPLAY SPEED:</span>
            <div className="flex items-center gap-1 bg-slate-900 border border-slate-700 rounded-lg p-1">
              {[0.5, 1, 2, 5, 10].map((s) => (
                <button
                  key={s}
                  onClick={() => handleSpeedSelect(s)}
                  className={`px-2.5 py-1 text-xs font-mono font-bold rounded ${
                    speed === s
                      ? "bg-cyan-500 text-slate-950"
                      : "text-slate-400 hover:text-white"
                  } transition-all cursor-pointer`}
                >
                  {s}x
                </button>
              ))}
            </div>
          </div>

          {/* Counters */}
          <div className="flex items-center gap-4 text-xs font-mono">
            <div>
              <span className="text-slate-500">FLOWS:</span>{" "}
              <span className="text-cyan-400 font-bold">{flowsStreamed}</span>
            </div>
            <div>
              <span className="text-slate-500">THREATS:</span>{" "}
              <span className="text-rose-400 font-bold">{threatsStreamed}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Scenario Deck */}
      <div>
        <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
          <Radio className="w-4 h-4 text-cyan-400" />
          Select Traffic Scenario to Replay
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scenarios.map((sc) => {
            const isCurrent = activeScenario === sc.id
            return (
              <div
                key={sc.id}
                onClick={() => handleStart(sc.id)}
                className={`bg-slate-900/80 border p-5 rounded-2xl cursor-pointer hover:border-cyan-500/60 transition-all space-y-3 relative overflow-hidden group shadow-lg ${
                  isCurrent ? "border-cyan-500 ring-1 ring-cyan-500/40" : "border-slate-800"
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="font-bold text-sm text-white group-hover:text-cyan-300 transition-colors">
                    {sc.title}
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    {sc.flows}
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  {sc.description}
                </p>

                <div className="pt-2 flex items-center justify-between text-xs font-mono">
                  <span className="text-cyan-400 group-hover:underline flex items-center gap-1 font-bold">
                    <Play className="w-3 h-3 fill-current" /> Replay Scenario
                  </span>
                  {isCurrent && streamState === "RUNNING" && (
                    <span className="text-emerald-400 flex items-center gap-1 text-[11px] font-bold">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                      ACTIVE
                    </span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
