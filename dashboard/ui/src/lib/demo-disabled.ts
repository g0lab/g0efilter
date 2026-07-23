import type { AggregateResponse, BrowseResponse, LogEntry } from './types';

export const DEMO = false;

function disabled(): never {
  throw new Error('demo mode is disabled');
}

export function demoLiveEvent(): LogEntry {
  return disabled();
}

export function demoConfig(): Record<string, unknown> {
  return disabled();
}

export function demoLogs(_params: URLSearchParams): LogEntry[] {
  return disabled();
}

export function demoBrowse(_params: URLSearchParams): BrowseResponse {
  return disabled();
}

export function demoAggregate(_params: URLSearchParams): AggregateResponse {
  return disabled();
}
