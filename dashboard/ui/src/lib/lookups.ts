export type LookupKind = 'domain' | 'ip';

export interface LookupProvider {
  id: string;
  label: string;
  name: string;
  kinds: readonly LookupKind[];
  url: (value: string) => string;
}

export interface LookupLink {
  id: string;
  label: string;
  name: string;
  value: string;
  url: string;
}

export const lookupProviders: readonly LookupProvider[] = [
  {
    id: 'virustotal',
    label: 'VT',
    name: 'VirusTotal',
    kinds: ['domain', 'ip'],
    url: (value) => 'https://www.virustotal.com/gui/search?query=' + encodeURIComponent(value),
  },
];

export function lookupLinks(rawValue: string, kind?: LookupKind): LookupLink[] {
  const target = normalizeLookupTarget(rawValue, kind);
  if (!target) return [];

  return lookupProviders
    .filter((provider) => provider.kinds.includes(target.kind))
    .map((provider) => ({
      id: provider.id,
      label: provider.label,
      name: provider.name,
      value: target.value,
      url: provider.url(target.value),
    }));
}

function normalizeLookupTarget(rawValue: string, hintedKind?: LookupKind): { value: string; kind: LookupKind } | null {
  let value = rawValue.trim();
  if (!value) return null;

  if (value.startsWith('[')) {
    const bracketed = value.match(/^\[([^\]]+)\](?::\d+)?$/);
    if (!bracketed) return null;
    value = bracketed[1];
  } else {
    const hostPort = value.match(/^([^:]+):(\d+)$/);
    if (hostPort) value = hostPort[1];
  }

  const kind = hintedKind || inferLookupKind(value);
  if (!kind || !isLookupValue(value, kind)) return null;
  return { value, kind };
}

function inferLookupKind(value: string): LookupKind | null {
  if (isLookupValue(value, 'ip')) return 'ip';
  if (isLookupValue(value, 'domain')) return 'domain';
  return null;
}

function isLookupValue(value: string, kind: LookupKind): boolean {
  if (kind === 'ip') return isIPv4(value) || isIPv6(value);
  return value.length <= 253
    && value.includes('.')
    && !value.includes('..')
    && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.?$/i.test(value);
}

function isIPv4(value: string): boolean {
  const octets = value.split('.');
  return octets.length === 4 && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

function isIPv6(value: string): boolean {
  return value.includes(':') && /^[0-9a-f:.]+$/i.test(value);
}
