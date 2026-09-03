export interface HeaderReader {
  get(name: string): string | null;
}

export interface RegistryFreshnessEvidence {
  ageSeconds: number | null;
  maxAgeSeconds: number | null;
  observedAtSeconds: number | null;
  responseDateSeconds: number | null;
}

export function registryFreshnessFromHeaders(
  headers: HeaderReader,
  observedAtSeconds: number
): RegistryFreshnessEvidence;
