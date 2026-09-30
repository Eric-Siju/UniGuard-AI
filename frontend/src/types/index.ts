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
