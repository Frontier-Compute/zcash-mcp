export type ReceiverDecision = "OBSERVATION_ONLY" | "ACCEPTED_HISTORICAL_ONLY" | "REJECTED" | "UNKNOWN_BLOCKED";

export interface ObservationInputs {
  receipt: unknown;
  receiptRaw: Uint8Array;
  registry: unknown;
  registryRaw: Uint8Array;
  actionInstance: unknown;
  unitContract: unknown;
  policy?: Record<string, unknown>;
}

export interface ObservationResult {
  schema: "frontier-compute.insight-receiver-result.v2";
  decision: ReceiverDecision;
  current_action_eligible: false;
  signature_state: "VERIFIED" | "NOT_VERIFIED";
  cryptographic_signature_state: "CRYPTOGRAPHIC_SIGNATURE_VALID" | "INVALID_OR_NOT_VERIFIED";
  recovered_signer_matches_selected_key: boolean;
  issuer_key_continuity_state: string;
  registry_status_state: string;
  receipt_policy_state: string;
  observation_state: "OBSERVATION_ONLY" | "NOT_ACCEPTED";
  action_state: "ACTION_AUTHORIZATION_BLOCKED";
  code: string;
  stage: string;
  retryable: boolean;
  customer_message: string;
  operator_action: string;
  trust: null | {
    bundle_sha256: string;
    bundle_epoch: number;
    registry_sha256: string;
    key_id?: string;
    signer?: string;
    key_admission?: string;
    issuer_succession_proof?: "UNRESOLVED" | "FROZEN_PREDECESSOR";
  };
  time: Record<string, unknown>;
  receipt: null | { uid?: string; transport_sha256: string; transport_source: string };
  evidence: null | { schema: string; hash: string };
  verification: unknown;
  binding: null;
  zap1_external_action_args: null;
  zap1_agent_action_args: null;
  non_authorizations: string[];
  transport_status?: RegistryTransportStatus;
  registry_transport_blocker_code?: string;
}

export interface RegistryTransportStatus {
  state: string;
  age_seconds: number | null;
  server_max_age_seconds: number | null;
  local_max_age_seconds: number;
  observed_at_seconds: number | null;
  response_date_seconds: number | null;
  blocker_code: string | null;
}

export function verifyCurrentObservation(args: ObservationInputs): ObservationResult;
export function verifyHistoricalObservation(args: ObservationInputs & { atSeconds: number }): ObservationResult;
export function gateRegistryStatusFreshness(
  result: ObservationResult,
  status: {
    ageSeconds: number | null;
    maxAgeSeconds: number | null;
    observedAtSeconds: number | null;
    responseDateSeconds: number | null;
  }
): ObservationResult & { transport_status: RegistryTransportStatus };

export function unavailableCurrentObservation(detail: unknown): ObservationResult;
export function evaluatePinnedKeyLifecycle(
  key: { validFrom: string; validUntil: string | null },
  checkedAt: number
): { ok: boolean; code: string; valid_from?: number; valid_until?: number | null };

export function parseStrictJsonBytes(
  value: Uint8Array,
  field: string,
  maximum: number
): { bytes: Uint8Array; parsed: unknown; sha256: string };

export const ROTATION_OBSERVER_VERSION: string;
export const TRUST_BUNDLE_V2: Readonly<Record<string, unknown>>;
export const TRUST_BUNDLE_V2_SHA256: string;
export const MAX_REGISTRY_STATUS_AGE_SECONDS: number;
export const MAX_HTTP_DATE_SKEW_SECONDS: number;
