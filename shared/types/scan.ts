export type ScanMode = "real" | "simulated" | "failed";

export type ScanFailureReason =
  | "binary_not_found"
  | "timeout"
  | "connection_refused"
  | "scope_blocked"
  | "parse_error"
  | "execution_error"
  | string;

export interface ScanStatus {
  tool: string;
  target_id: string;
  target_url?: string | null;
  started_at: string;
  finished_at: string;
  duration_sec: number;
  mode: ScanMode;
  reason?: ScanFailureReason | null;
  exit_code: number;
  binary_available: boolean;
  evidence_trustworthy: boolean;
  raw_path?: string | null;
  raw_sha256?: string | null;
  raw_size_bytes?: number;
  finding_count: number;
  warnings?: string[];
  errors?: string[];
}

export interface ScanMetadata {
  tool: string;
  target: string;
  command: string;
  arguments: string;
  timestamp: string;
  duration_seconds: number;
  exit_code: number;
}

export interface EvidenceFileItem {
  name: string;
  path?: string;
  rel_path?: string;
  type: "raw" | "normal" | "structured" | "log" | "simulated" | "status";
  tool: string;
  size_bytes?: number;
}

export interface ScanItem {
  target_id: string;
  target_host?: string;
  tools: string[];
  timestamp?: string;
  evidence_files: EvidenceFileItem[];
  tool_statuses?: Record<string, ScanStatus>;
}
