/* Domain types mirroring the dashboard JSON API (dashboard/model). */

export interface LogEntry {
  id?: number;
  time?: string;
  ts?: string;
  msg?: string;
  fields?: Record<string, unknown> | string;
  action?: string;
  component?: string;
  source_ip?: string;
  source_port?: number;
  destination_ip?: string;
  destination_port?: number;
  protocol?: string;
  http_host?: string;
  https?: string;
  host?: string;
  qname?: string;
  hostname?: string;
  flow_id?: string;
  version?: string;
  src?: string;
  dst?: string;
  type?: string; // SSE control frames: cleared or unblock_status
}

export interface APIKey {
  id: string;
  label: string;
  prefix: string;
  created_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
}

export interface Group {
  id: string;
  name: string;
  policy: string;
  filter_mode?: string;
  updated_at: string;
}

export interface Instance {
  id: string;
  hostname: string;
  group_id?: string;
  group_name?: string;
  policy_override?: string | null;
  filter_mode?: string;
  reported_version?: string;
  reported_hash?: string;
  desired_hash?: string;
  in_sync: boolean;
  last_seen_at: string;
  created_at: string;
}

export interface UnblockStatus {
  value: string;
  target_hostname?: string;
}

export interface DashboardConfig {
  buffer_size?: number;
  read_limit?: number;
  auth_mode?: string;
  fleet_enabled?: boolean;
}

export type ToastKind = 'info' | 'ok' | 'err';

export interface Bucket {
  label: string;
  allowed: number;
  blocked: number;
}

export interface BarItem {
  label: string;
  value: number;
}
