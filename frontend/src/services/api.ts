import { SystemStats, Alert, FlowRecord, ThreatSummary, ModelMetadata, BenchmarkResult, WebSocketEvent } from "../types"

const API_BASE = ""

export async function fetchStats(): Promise<SystemStats> {
  const res = await fetch(`${API_BASE}/api/stats`)
  if (!res.ok) throw new Error("Failed to fetch stats")
  return res.json()
}

export async function fetchAlerts(params?: { threat_type?: string; severity?: string; limit?: number; offset?: number }): Promise<{ total: number; items: Alert[] }> {
  const query = new URLSearchParams()
  if (params?.threat_type && params.threat_type !== "All") query.append("threat_type", params.threat_type)
  if (params?.severity && params.severity !== "All") query.append("severity", params.severity)
  if (params?.limit) query.append("limit", params.limit.toString())
  if (params?.offset) query.append("offset", params.offset.toString())
  
  const res = await fetch(`${API_BASE}/api/alerts?${query.toString()}`)
  if (!res.ok) throw new Error("Failed to fetch alerts")
  return res.json()
}

export async function fetchAlertDetail(alertId: string): Promise<{ alert: Alert; related_flows: FlowRecord[] }> {
  const res = await fetch(`${API_BASE}/api/alerts/${alertId}`)
  if (!res.ok) throw new Error("Failed to fetch alert detail")
  return res.json()
}

export async function fetchThreatsSummary(): Promise<ThreatSummary> {
  const res = await fetch(`${API_BASE}/api/threats/summary`)
  if (!res.ok) throw new Error("Failed to fetch threat summary")
  return res.json()
}

export async function fetchFlows(params?: { threat_label?: string; protocol?: string; search?: string; limit?: number; offset?: number }): Promise<{ total: number; items: FlowRecord[] }> {
  const query = new URLSearchParams()
  if (params?.threat_label && params.threat_label !== "All") query.append("threat_label", params.threat_label)
  if (params?.protocol && params.protocol !== "All") query.append("protocol", params.protocol)
  if (params?.search) query.append("search", params.search)
  if (params?.limit) query.append("limit", params.limit.toString())
  if (params?.offset) query.append("offset", params.offset.toString())

  const res = await fetch(`${API_BASE}/api/flows?${query.toString()}`)
  if (!res.ok) throw new Error("Failed to fetch flows")
  return res.json()
}

export async function fetchModelEvaluation(): Promise<ModelMetadata> {
  const res = await fetch(`${API_BASE}/api/model/evaluation`)
  if (!res.ok) throw new Error("Failed to fetch model evaluation")
  return res.json()
}

export async function triggerTrainModel(): Promise<{ status: string; message: string; metadata: ModelMetadata }> {
  const res = await fetch(`${API_BASE}/api/model/train`, { method: "POST" })
  if (!res.ok) throw new Error("Failed to train model")
  return res.json()
}

export async function startDemoStream(scenario: string = "combined_demo", speed: number = 1.0): Promise<any> {
  const res = await fetch(`${API_BASE}/api/demo/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario, speed })
  })
  return res.json()
}

export async function pauseDemoStream(): Promise<any> {
  const res = await fetch(`${API_BASE}/api/demo/pause`, { method: "POST" })
  return res.json()
}

export async function resumeDemoStream(): Promise<any> {
  const res = await fetch(`${API_BASE}/api/demo/resume`, { method: "POST" })
  return res.json()
}

export async function stopDemoStream(): Promise<any> {
  const res = await fetch(`${API_BASE}/api/demo/stop`, { method: "POST" })
  return res.json()
}

export async function runBenchmark(): Promise<BenchmarkResult> {
  const res = await fetch(`${API_BASE}/api/benchmark`)
  if (!res.ok) throw new Error("Failed to run benchmark")
  return res.json()
}

export async function fetchSettings(): Promise<any> {
  const res = await fetch(`${API_BASE}/api/settings`)
  return res.json()
}

export async function updateSettings(settings: any): Promise<any> {
  const res = await fetch(`${API_BASE}/api/settings`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(settings)
  })
  return res.json()
}

export async function uploadDataset(file: File, type: "csv" | "pcap"): Promise<any> {
  const formData = new FormData()
  formData.append("file", file)
  const res = await fetch(`${API_BASE}/api/upload/${type}`, {
    method: "POST",
    body: formData
  })
  if (!res.ok) {
    const err = await res.json()
    throw new Error(err.detail || "Upload failed")
  }
  return res.json()
}

export async function updateAlertLifecycle(alertId: string, data: { status?: string; analyst_note?: string; tags?: string[] }): Promise<Alert> {
  const res = await fetch(`${API_BASE}/api/alerts/${alertId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  })
  if (!res.ok) throw new Error("Failed to update alert lifecycle")
  return res.json()
}

export async function acknowledgeAlert(alertId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/alerts/${alertId}/acknowledge`, { method: "POST" })
  return res.json()
}

export async function fetchCases(): Promise<any[]> {
  const res = await fetch(`${API_BASE}/api/cases`)
  if (!res.ok) throw new Error("Failed to fetch cases")
  return res.json()
}

export async function createCase(data: { title: string; description?: string; severity?: string; related_alerts?: string[]; related_assets?: string[]; tags?: string[]; analyst_note?: string }): Promise<any> {
  const res = await fetch(`${API_BASE}/api/cases`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  })
  if (!res.ok) throw new Error("Failed to create case")
  return res.json()
}

export async function fetchCaseDetail(caseId: string): Promise<{ case: any; alerts: Alert[] }> {
  const res = await fetch(`${API_BASE}/api/cases/${caseId}`)
  if (!res.ok) throw new Error("Failed to fetch case detail")
  return res.json()
}

export async function updateCase(caseId: string, data: any): Promise<any> {
  const res = await fetch(`${API_BASE}/api/cases/${caseId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  })
  if (!res.ok) throw new Error("Failed to update case")
  return res.json()
}

export async function exportCaseReportUrl(caseId: string): Promise<string> {
  return `${API_BASE}/api/cases/${caseId}/export`
}

export async function fetchAssets(): Promise<{ total_assets: number; assets: any[] }> {
  const res = await fetch(`${API_BASE}/api/assets`)
  if (!res.ok) throw new Error("Failed to fetch assets")
  return res.json()
}

export async function fetchAssetDetail(ip: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/assets/${ip}`)
  if (!res.ok) throw new Error("Failed to fetch asset detail")
  return res.json()
}

export async function fetchCampaigns(): Promise<{ total_campaigns: number; campaigns: any[] }> {
  const res = await fetch(`${API_BASE}/api/campaigns`)
  if (!res.ok) throw new Error("Failed to fetch campaigns")
  return res.json()
}

export async function fetchThreatIntel(): Promise<{ total: number; indicators: any[]; mode: string }> {
  const res = await fetch(`${API_BASE}/api/threat-intel`)
  if (!res.ok) throw new Error("Failed to fetch threat intel")
  return res.json()
}

export async function addThreatIntel(data: { indicator_type: string; indicator: string; description?: string; source?: string; severity?: string }): Promise<any> {
  const res = await fetch(`${API_BASE}/api/threat-intel`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  })
  if (!res.ok) throw new Error("Failed to add threat intel")
  return res.json()
}

export async function fetchDataSources(): Promise<{ total_sources: number; sources: any[]; unidirectional_mode: boolean }> {
  const res = await fetch(`${API_BASE}/api/datasources`)
  if (!res.ok) throw new Error("Failed to fetch data sources")
  return res.json()
}

export async function uploadZeekJson(file: File): Promise<any> {
  const formData = new FormData()
  formData.append("file", file)
  const res = await fetch(`${API_BASE}/api/upload/zeek`, {
    method: "POST",
    body: formData
  })
  if (!res.ok) {
    const err = await res.json()
    throw new Error(err.detail || "Zeek upload failed")
  }
  return res.json()
}

export async function uploadSuricataEve(file: File): Promise<any> {
  const formData = new FormData()
  formData.append("file", file)
  const res = await fetch(`${API_BASE}/api/upload/eve`, {
    method: "POST",
    body: formData
  })
  if (!res.ok) {
    const err = await res.json()
    throw new Error(err.detail || "Suricata EVE upload failed")
  }
  return res.json()
}

export async function fetchAssurance(): Promise<any> {
  const res = await fetch(`${API_BASE}/api/assurance`)
  if (!res.ok) throw new Error("Failed to fetch assurance")
  return res.json()
}

export async function executeThreatHunt(params: {
  src_ip?: string
  dst_ip?: string
  protocol?: string
  threat_type?: string
  limit?: number
  offset?: number
}): Promise<{ total: number; items: any[] }> {
  const query = new URLSearchParams()
  if (params.src_ip) query.append("src_ip", params.src_ip)
  if (params.dst_ip) query.append("dst_ip", params.dst_ip)
  if (params.protocol && params.protocol !== "All") query.append("protocol", params.protocol)
  if (params.threat_type && params.threat_type !== "All") query.append("threat_type", params.threat_type)
  if (params.limit) query.append("limit", params.limit.toString())
  if (params.offset) query.append("offset", params.offset.toString())

  const res = await fetch(`${API_BASE}/api/hunt?${query.toString()}`)
  if (!res.ok) throw new Error("Failed to execute hunt")
  return res.json()
}


// Real-time WebSocket connection hook helper
export function createAlertsWebSocket(
  onMessage: (event: WebSocketEvent) => void,
  onStatusChange?: (connected: boolean) => void
) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:"
  const host = window.location.host
  // If in dev proxy or direct port, fallback cleanly
  const wsUrl = `${protocol}//${host}/ws/alerts`
  
  let ws: WebSocket | null = null
  let reconnectTimer: any = null

  function connect() {
    try {
      ws = new WebSocket(wsUrl)
      
      ws.onopen = () => {
        onStatusChange?.(true)
        if (reconnectTimer) clearTimeout(reconnectTimer)
      }
      
      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          onMessage(data)
        } catch (err) {
          console.error("WS Parse error", err)
        }
      }
      
      ws.onclose = () => {
        onStatusChange?.(false)
        reconnectTimer = setTimeout(connect, 3000)
      }
      
      ws.onerror = () => {
        ws?.close()
      }
    } catch (err) {
      onStatusChange?.(false)
      reconnectTimer = setTimeout(connect, 3000)
    }
  }

  connect()

  return {
    disconnect: () => {
      if (reconnectTimer) clearTimeout(reconnectTimer)
      ws?.close()
    }
  }
}
