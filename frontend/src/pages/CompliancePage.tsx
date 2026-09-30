import React from "react"
import {
  Lock,
  ShieldCheck,
  ArrowDown,
  Eye,
  Slash,
  KeyRound,
  FileCheck,
  ServerOff,
  CheckCircle2,
  HardDrive
} from "lucide-react"

export const CompliancePage: React.FC = () => {
  const pipelineSteps = [
    {
      title: "1. PASSIVE INPUT",
      desc: "Physical TAP / Optical Diode receives light or electrical signals unidirectionally. Transmit lines (Tx) physically cut or disconnected.",
      icon: Eye,
      color: "border-cyan-500/40 text-cyan-400 bg-cyan-950/40"
    },
    {
      title: "2. OBSERVATION ONLY",
      desc: "Network interfaces are configured in promiscuous, non-responding mode. The host IP stack drops all outbound ARP, ICMP, and TCP acknowledgments.",
      icon: ShieldCheck,
      color: "border-blue-500/40 text-blue-400 bg-blue-950/40"
    },
    {
      title: "3. ZERO ACTIVE SCANNING",
      desc: "The monitoring platform never originates SYN packets, UDP probes, or banner grabbing against detected or monitored endpoints.",
      icon: Slash,
      color: "border-purple-500/40 text-purple-400 bg-purple-950/40"
    },
    {
      title: "4. NO NETWORK RESPONSE",
      desc: "Strictly passive. No TCP RST injections, DNS spoofing, or active inline blocking that could compromise monitored network isolation.",
      icon: ServerOff,
      color: "border-amber-500/40 text-amber-400 bg-amber-950/40"
    },
    {
      title: "5. NO PAYLOAD DECRYPTION",
      desc: "Encrypted TLS/QUIC channels remain unmolested. Detection relies exclusively on observable metadata: SNI entropy, timing jitter, and record size sequences.",
      icon: KeyRound,
      color: "border-rose-500/40 text-rose-400 bg-rose-950/40"
    },
    {
      title: "6. ALERTING ONLY",
      desc: "Security alerts, telemetry, and forensics are routed exclusively downstream to SOC analysts via a dedicated, physically isolated management network.",
      icon: CheckCircle2,
      color: "border-emerald-500/40 text-emerald-400 bg-emerald-950/40"
    }
  ]

  return (
    <div className="space-y-6 p-6">
      {/* Top Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
        <h1 className="text-base font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Lock className="w-5 h-5 text-cyan-400" />
          Unidirectional Diode & Security Compliance Architecture
        </h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Rigorous mathematical and hardware compliance with Smart India Hackathon problem statement SIH26145
        </p>
      </div>

      {/* Mandatory Unidirectional Flow Diagram */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Eye className="w-4 h-4 text-cyan-400" />
          Mandatory Unidirectional Data Flow Proof
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pt-2">
          {pipelineSteps.map((step, idx) => {
            const Icon = step.icon
            return (
              <div
                key={idx}
                className={`p-5 rounded-xl border ${step.color} space-y-2 relative shadow-md`}
              >
                <div className="flex items-center gap-2">
                  <Icon className="w-5 h-5 shrink-0" />
                  <span className="font-extrabold text-xs tracking-wider text-white">
                    {step.title}
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {step.desc}
                </p>
              </div>
            )
          })}
        </div>
      </div>

      {/* Physical Data Diode Wiring Diagram Card */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <HardDrive className="w-4 h-4 text-cyan-400" />
          Hardware Data Diode Interface Topology
        </h2>

        <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 font-mono text-xs text-slate-300 space-y-2">
          <pre className="text-cyan-400 overflow-x-auto">
{`+------------------------------+             +-------------------------------+             +------------------------------+
|     Monitored Subnet /       |  Optical    |    Hardware Data Diode /      |   Ethernet  |      UniGuard AI Engine      |
|    Air-Gapped Critical OT    |  Fiber Tx   |    Physical Passive TAP       |   Rx Only   |     (Passive Observer)       |
|                              | ----------->|                               | ----------->|                              |
|   [Active Network Segment]   | (No Return) |   [Tx Photodiode physically   | (Promisc)   |   - Scapy Header Parsing     |
|                              |             |    severed / non-existent]    |             |   - Multi-Signal Rule Engine |
+------------------------------+             +-------------------------------+             |   - Random Forest ML         |
                                                                                           |   - Isolation Forest Anomaly |
                                                                                           +------------------------------+
                                                                                                         |
                                                                                                         v (Isolated Mgmt LAN)
                                                                                           +------------------------------+
                                                                                           |    SOC Analyst Dashboard     |
                                                                                           |    (WebSockets / Reports)    |
                                                                                           +------------------------------+`}
          </pre>
        </div>
      </div>

      {/* Software Application Security Measures */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <FileCheck className="w-4 h-4 text-emerald-400" />
          Application Hardening & Defense-in-Depth
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-sans">
          <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-1">
            <span className="font-bold text-white flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              Safe File Upload & Size Limits
            </span>
            <p className="text-slate-400 leading-relaxed">
              Uploads are restricted to 50MB and validated against strict whitelists (.pcap, .pcapng, .csv). Files are sanitized to prevent directory traversal or malicious overwrite.
            </p>
          </div>

          <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-1">
            <span className="font-bold text-white flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              Zero Command Injection
            </span>
            <p className="text-slate-400 leading-relaxed">
              Packet dissections and statistical computations execute entirely in native Python/Scapy memory without spawning external shell processes or invoking subshells.
            </p>
          </div>

          <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-1">
            <span className="font-bold text-white flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              100% Offline-First Architecture
            </span>
            <p className="text-slate-400 leading-relaxed">
              Zero telemetry calls to cloud APIs or external LLMs. Model inference and anomaly detectors execute entirely on local CPU memory, making it ideal for air-gapped SCADA / defence networks.
            </p>
          </div>

          <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-1">
            <span className="font-bold text-white flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              Strict Path Traversal Protection
            </span>
            <p className="text-slate-400 leading-relaxed">
              All file paths and uploaded datasets are resolved against sanitized base directories using <code className="text-cyan-400 font-mono">Path.resolve()</code> to prevent directory traversal attacks.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
