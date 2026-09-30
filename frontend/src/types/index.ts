export interface FlowRecord {
  id?: number
  flow_id: string
  timestamp: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  duration: number
  total_bytes: number
  total_packets: number
  packets_per_sec: number
  bytes_per_sec: number
  tcp_flags?: string
  dns_query?: string
  sni?: string
  is_encrypted: boolean
  threat_label: string
  risk_score: number
}

export interface ContributingFeature {
  feature: string
  name: string
  value: number
  impact: number
  importance: number
}

export interface Alert {
  id?: number
  alert_id: string
  timestamp: string
  threat_type: string
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  confidence: number
  risk_score: number
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  duration: number
  total_bytes: number
  total_packets: number
  evidence: string[]
  rule_matches: string[]
  ml_prediction?: string
  ml_confidence?: number
  contributing_features: ContributingFeature[]
  flow_id: string
  acknowledged?: boolean
  status?: "NEW" | "ACKNOWLEDGED" | "INVESTIGATING" | "RESOLVED"
  analyst_note?: string
  tags?: string[]
  occurrences?: number
  first_seen?: string
  last_seen?: string
  suppressed_count?: number
  mitre_technique_id?: string
  mitre_technique_name?: string
  mitre_tactic?: string
  baseline_deviation?: string
  threat_intel_match?: any
}

export interface Case {
  id?: number
  case_id: string
  title: string
  description: string
  status: "OPEN" | "INVESTIGATING" | "CLOSED"
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  created_at: string
  updated_at: string
  related_alerts: string[]
  related_assets: string[]
  analyst_notes: Array<{ timestamp: string; author: string; note: string }>
  tags: string[]
}

export interface AssetRiskFactor {
  factor: string
  points: number
  description: string
}

export interface Asset {
  ip: string
  role: string
  first_observed: string
  last_observed: string
  bytes_in: number
  bytes_out: number
  flows_count: number
  unique_ports: number
  destinations_count: number
  threat_count: number
  risk_score: number
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  risk_factors: AssetRiskFactor[]
}

export interface ThreatIntelIndicator {
  id?: number
  indicator_type: string
  indicator: string
  description: string
  source: string
  severity: string
  created_at?: string
}

export interface DataSourceInfo {
  source: string
  type: string
  status: string
  records_received: number
  records_parsed: number
  records_rejected: number
  last_event: string
  processing_rate: string
  errors: string[]
}

export interface AttackCampaign {
  campaign_id: string
  title: string
  entity_ip: string
  threat_count: number
  distinct_stages: number
  campaign_risk: number
  status: string
  phases: Array<{
    phase_name: string
    threat_type: string
    tactic: string
    description: string
  }>
  timeline: Array<{
    alert_id: string
    threat_type: string
    severity: string
    timestamp: string
    target: string
    evidence: string[]
  }>
  created_at: string
  updated_at: string
  recommended_action: string
}

export interface SystemStats {
  flows_processed: number
  packets_processed: number
  threats_detected: number
  suspicious_flows: number
  current_risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  processing_latency_ms: number
  packets_per_sec: number
  flows_per_sec: number
  cpu_percent: number
  memory_mb: number
  passive_mode: boolean
  read_only_status: boolean
  active_response: boolean
  current_fps?: number
  avg_latency_ms?: number
}

export interface ThreatSummary {
  total_threats: number
  threat_distribution: Record<string, number>
  severity_distribution: Record<string, number>
  top_attackers: Array<{ ip: string; count: number }>
  top_targeted_ports: Array<{ port: number; count: number }>
}

export interface ModelMetadata {
  model_name: string
  model_type: string
  version: string
  training_timestamp: string
  dataset_name: string
  sample_count: number
  feature_count: number
  classes: string[]
  accuracy: number
  precision: number
  recall: number
  f1_score: number
  confusion_matrix: number[][]
  classification_report: Record<string, any>
  false_positive_rate: number
  false_negative_rate: number
  top_features: Array<{ feature: string; display_name: string; importance: number }>
  all_features: Array<{ feature: string; display_name: string; importance: number }>
  is_active: boolean
}

export interface BenchmarkResult {
  timestamp: string
  machine_info: {
    os: string
    processor: string
    cpu_cores: number
    python_version: string
  }
  sample_size: number
  throughput_flows_per_sec: number
  avg_pipeline_latency_ms: number
  avg_feature_extraction_ms: number
  p95_feature_extraction_ms: number
  avg_ml_inference_ms: number
  p95_ml_inference_ms: number
  avg_rule_evaluation_ms: number
  memory_usage_mb: number
  cpu_usage_percent: number
  alerts_generated: number
  status_label: string
}

export type WebSocketEvent =
  | {
      type: "init_status"
      state: string
      speed: number
      scenario: string
      stats: SystemStats
    }
  | {
      type: "flow_event"
      flow: FlowRecord
      alert?: Alert | null
    }
  | {
      type: "stats_update"
      stats: Partial<SystemStats> & { current_fps?: number }
    }
  | {
      type: "state_change" | "demo_state"
      state: string
      speed?: number
      scenario?: string
    }
