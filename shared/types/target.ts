export type TargetType =
  | "ipv4"
  | "ipv6"
  | "cidr"
  | "domain"
  | "hostname"
  | "url"
  | "host_port"
  | "custom";

export type TargetStatus = "active" | "archived" | "blocked";

export interface TargetScope {
  allowed_ports: number[];
  forbidden_ports: number[];
  allowed_attacks: string[];
  forbidden_attacks: string[];
  is_in_scope: boolean;
  scope_rule?: string | null;
}

export interface Target {
  target_id: str;
  campaign_id: string;
  name: string;
  type: TargetType;
  raw_input: string;
  normalized_value: string;
  host: string;
  port?: number | null;
  scheme?: string | null;
  path?: string | null;
  environment: string;
  scope: TargetScope;
  tags: string[];
  status: TargetStatus;
  created_at: string;
  updated_at: string;
}

export interface TargetDetectRequest {
  input: string;
  campaign_id?: string;
}

export interface TargetDetectResponse {
  raw_input: string;
  target_type: TargetType;
  normalized_value: string;
  host: string;
  port?: number | null;
  scheme?: string | null;
  is_valid: boolean;
  syntax_errors: string[];
  scope: {
    allowed: boolean;
    reason: string;
    matched_rule?: string | null;
  };
  recommended_tools: string[];
}
