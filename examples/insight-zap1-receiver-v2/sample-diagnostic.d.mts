export interface CapturedSampleDiagnosticResult {
  readonly schema: "frontier-compute.insight-captured-sample-diagnostic.v1";
  readonly decision: "UNKNOWN_BLOCKED";
  readonly code: string;
  readonly diagnostic_valid: boolean;
  readonly signature_state: "VERIFIED" | "NOT_VERIFIED";
  readonly cryptographic_signature_state: "CRYPTOGRAPHIC_SIGNATURE_VALID" | "INVALID_OR_NOT_VERIFIED";
  readonly observation_state: "NOT_ACCEPTED";
  readonly replay_state: "NOT_COMMITTED";
  readonly current_action_eligible: false;
  readonly action_state: "ACTION_AUTHORIZATION_BLOCKED";
  readonly action_authorized: false;
  readonly binding: null;
  readonly zap1_external_action_args: null;
  readonly zap1_agent_action_args: null;
  readonly evaluated_at_seconds: number | null;
  readonly registry_transport_sha256: string | null;
  readonly sample_transport_sha256: string | null;
  readonly receipt_uid: string | null;
  readonly sample_signer: string | null;
  readonly detail: string;
  readonly verification: null | {
    readonly ok?: boolean;
    readonly native?: {
      readonly recoveredSigner?: string;
      readonly checkedAt?: number;
      readonly validUntil?: number;
      readonly selectedKey?: {
        readonly signer?: string;
        readonly validFrom?: string;
        readonly validUntil?: string | null;
      };
    };
  };
}

export interface CapturedSampleDiagnosticInput {
  readonly registryRaw: Uint8Array;
  readonly sampleRaw: Uint8Array;
  readonly actionInstance: unknown;
  readonly unitContract: unknown;
  readonly atSeconds: number;
  readonly policy?: Record<string, unknown>;
}

export function verifyCapturedSampleDiagnostic(
  input: CapturedSampleDiagnosticInput,
): CapturedSampleDiagnosticResult;
