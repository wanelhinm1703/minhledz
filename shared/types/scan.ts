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
  path: string;
  type: "raw" | "normal" | "structured" | "log";
  tool: string;
  size_bytes?: number;
}

export interface ScanItem {
  target_id: string;
  target_host: string;
  tools: string[];
  timestamp: string;
  evidence_files: EvidenceFileItem[];
}
