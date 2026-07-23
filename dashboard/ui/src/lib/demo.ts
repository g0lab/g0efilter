/* Static demo data, shared with the Go development tools. */
import scenariosData from '$demo-fixtures/scenarios.json';
import { createDemoRuntime, type DemoFixtures } from './demo-data';
import type { AggregateResponse, BrowseResponse, DashboardConfig, LogEntry } from './types';

export const DEMO = true;

const runtime = createDemoRuntime(scenariosData as DemoFixtures);

export function demoLiveEvent(): LogEntry {
  return runtime.liveEvent();
}

export function demoConfig(): DashboardConfig {
  return runtime.config();
}

export function demoLogs(params: URLSearchParams): LogEntry[] {
  return runtime.logs(params);
}

export function demoBrowse(params: URLSearchParams): BrowseResponse {
  return runtime.browse(params);
}

export function demoAggregate(params: URLSearchParams): AggregateResponse {
  return runtime.aggregate(params);
}
