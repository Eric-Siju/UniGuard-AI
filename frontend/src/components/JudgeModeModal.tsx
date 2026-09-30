import React, { useState } from "react"
import { Award, ChevronRight, ChevronLeft, Play, CheckCircle2, ShieldCheck, X } from "lucide-react"
import { startDemoStream } from "../services/api"

interface JudgeModeModalProps {
  isOpen: boolean
  onClose: () => void
  onNavigateTab: (tab: any) => void
  onStreamStateChange: (state: string, scenario: string, speed: number) => void
}

interface Step {
  id: number
  title: string
  subtitle: string
  description: string
  actionLabel?: string
  targetTab: string
  scenarioToTrigger?: string
}

export const JudgeModeModal: React.FC<JudgeModeModalProps> = ({
  isOpen,
  onClose,
  onNavigateTab,
  onStreamStateChange
}) => {
  const [currentStep, setCurrentStep] = useState(0)
  const [isExecuting, setIsExecuting] = useState(false)

  const steps: Step[] = [
    {
      id: 1,
      title: "1. One-Way Diode Architecture",
      subtitle: "Unidirectional Passive Assurance",
      description:
        "Inspect the physical and application-enforced unidirectional tap topology. Verify that active response, packet injection, and payload decryption are strictly disabled.",
      actionLabel: "View Diode Architecture",
      targetTab: "compliance"
    },
    {
      id: 2,
      title: "2. Establish Benign Baseline",
      subtitle: "Learning Temporal Normal Dynamics",
      description:
        "Start normal baseline network traffic. Observe packet rates, byte velocities, and rolling baseline learning in passive mode.",
      actionLabel: "Stream Normal Baseline",
      targetTab: "dashboard",
      scenarioToTrigger: "normal"
    },
    {
      id: 3,
      title: "3. Trigger Reconnaissance (Port Scan)",
      subtitle: "Horizontal / Vertical Sweep Detection",
      description:
        "Simulate adversarial reconnaissance probe. Watch the multi-signal rule engine and Random Forest classifier detect short probes and high unique port diversity.",
      actionLabel: "Simulate Port Scan Attack",
      targetTab: "dashboard",
      scenarioToTrigger: "port_scan"
    },
    {
      id: 4,
      title: "4. Trigger Botnet C2 Beaconing",
      subtitle: "Statistical Heartbeat Cadence",
      description:
        "Observe periodic command-and-control beacons. Note how UniGuard requires repeated temporal observations and low interval jitter before escalating.",
      actionLabel: "Simulate Botnet C2 Beacons",
      targetTab: "dashboard",
      scenarioToTrigger: "botnet"
    },
    {
      id: 5,
      title: "5. Trigger DNS Tunneling & DGA",
      subtitle: "Protocol Concealment",
      description:
        "Inspect high-entropy DNS queries used for data tunneling. See how Shannon entropy and query length trigger multi-signal corroboration.",
      actionLabel: "Simulate DNS Tunneling",
      targetTab: "dashboard",
      scenarioToTrigger: "dns_tunneling"
    },
    {
      id: 6,
      title: "6. Trigger Data Exfiltration",
      subtitle: "Asymmetric Outbound Volume",
      description:
        "Observe massive outbound transfer without reciprocal traffic. The baseline deviation engine flags severe transmission volume shifts.",
      actionLabel: "Simulate Data Exfiltration",
      targetTab: "dashboard",
      scenarioToTrigger: "exfiltration"
    },
    {
      id: 7,
      title: "7. Attack Campaign Correlation",
      subtitle: "Connecting the Multi-Stage Intrusion",
      description:
        "Review how UniGuard correlates separate events from the same adversary into a single cohesive Attack Campaign narrative.",
      actionLabel: "Inspect Attack Campaigns",
      targetTab: "campaigns"
    },
    {
      id: 8,
      title: "8. Forensic Alert Investigation",
      subtitle: "Multi-Signal Consensus & Evidence",
      description:
        "Open a security alert. Review the 5-way consensus pipeline (Rule + ML + Anomaly + Intel + Baseline) and contributing feature importance weights.",
      actionLabel: "Open Investigation Console",
      targetTab: "investigation"
    },
    {
      id: 9,
      title: "9. Escalate to SOC Incident Case",
      subtitle: "Case Management & Dossiers",
      description:
        "Review open SOC cases, add forensic analyst notes, link affected assets, and generate an exportable incident report.",
      actionLabel: "Review SOC Cases",
      targetTab: "cases"
    },
    {
      id: 10,
      title: "10. Entity Risk Scoring",
      subtitle: "Explainable Asset Risk",
      description:
        "View the passive asset inventory. Note how each host receives a 0–100 risk score with transparent mathematical contributory factors.",
      actionLabel: "View Entity Risk Inventory",
      targetTab: "assets"
    },
    {
      id: 11,
      title: "11. MITRE ATT&CK Matrix",
      subtitle: "Standard Threat Classification",
      description:
        "Examine how detections map directly to official MITRE techniques (T1046, T1071, T1071.004, T1041, T1498).",
      actionLabel: "View Compliance & MITRE",
      targetTab: "compliance"
    },
    {
      id: 12,
      title: "12. Executive Audit Report",
      subtitle: "Official Audit Documentation",
      description:
        "Generate a formal, publication-ready security audit report with executive summary, technical metrics, and unidirectional disclaimers.",
      actionLabel: "View Security Audit Report",
      targetTab: "reports"
    }
  ]

  if (!isOpen) return null

  const step = steps[currentStep]

  const handleStepAction = async () => {
    setIsExecuting(true)
    try {
      if (step.scenarioToTrigger) {
        await startDemoStream(step.scenarioToTrigger, 2.0)
        onStreamStateChange("RUNNING", step.scenarioToTrigger, 2.0)
      }
      onNavigateTab(step.targetTab)
    } catch (err) {
      console.error(err)
    } finally {
      setIsExecuting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-6 shadow-2xl relative">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-slate-500 hover:text-slate-300 p-1"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 border-b border-slate-800 pb-4">
          <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400">
            <Award className="w-6 h-6" />
          </div>
          <div>
            <span className="text-[11px] font-mono font-bold text-amber-400 uppercase tracking-wider block">
              SIH26145 Evaluation Guide
            </span>
            <h3 className="text-lg font-bold text-slate-100">
              UniGuard AI &bull; Interactive Judge Demonstration
            </h3>
          </div>
        </div>

        {/* Step Progress Bar */}
        <div className="space-y-1.5">
          <div className="flex justify-between items-center text-xs font-mono text-slate-400">
            <span>
              Demonstration Step <strong className="text-cyan-400">{currentStep + 1}</strong> of {steps.length}
            </span>
            <span className="text-slate-500">
              {Math.round(((currentStep + 1) / steps.length) * 100)}% Complete
            </span>
          </div>
          <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
            <div
              className="bg-gradient-to-r from-cyan-500 to-amber-500 h-full transition-all duration-300"
              style={{ width: `${((currentStep + 1) / steps.length) * 100}%` }}
            />
          </div>
        </div>

        {/* Step Card Content */}
        <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex justify-between items-start">
            <div>
              <h4 className="text-base font-bold text-slate-100">{step.title}</h4>
              <span className="text-xs font-mono text-cyan-400">{step.subtitle}</span>
            </div>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">{step.description}</p>
        </div>

        {/* Step Action & Navigation */}
        <div className="flex flex-col sm:flex-row justify-between items-center gap-4 pt-2">
          <div className="flex gap-2 w-full sm:w-auto">
            <button
              onClick={() => setCurrentStep((p) => Math.max(0, p - 1))}
              disabled={currentStep === 0}
              className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 disabled:pointer-events-none transition-colors flex items-center gap-1 cursor-pointer"
            >
              <ChevronLeft className="w-4 h-4" /> Previous
            </button>
            <button
              onClick={() => setCurrentStep((p) => Math.min(steps.length - 1, p + 1))}
              disabled={currentStep === steps.length - 1}
              className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 disabled:pointer-events-none transition-colors flex items-center gap-1 cursor-pointer"
            >
              Next <ChevronRight className="w-4 h-4" />
            </button>
          </div>

          <div className="flex gap-3 w-full sm:w-auto justify-end">
            <button
              onClick={handleStepAction}
              disabled={isExecuting}
              className="px-5 py-2 rounded-lg text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-slate-950 transition-colors flex items-center gap-2 cursor-pointer shadow-md shadow-cyan-500/10"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {step.actionLabel || "Execute Step"}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
