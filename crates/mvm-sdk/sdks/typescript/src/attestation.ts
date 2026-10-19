/** Host identity data; a valid v0 signature is not measured-boot evidence. */
import { call } from "./_hostlib.js";
import { ATTESTATION_EXPORT, ATTESTATION_STATUS, ATTESTATION_VERIFY } from "./hostabi/methods.js";

export type Trust = { kind: "self_identity" } | { kind: "public_key_file"; path: string };
export interface ReportData { payload: number[]; signature: number[]; signer_id: string }
export interface HardwareMeasurementData { provider: string; measurement_hex: string }
export interface BodyData {
  schema_version: number;
  boot_measurement: string;
  identity_pubkey_hex: string;
  nonce_hex: string;
  hw_measurement: HardwareMeasurementData | null;
}
export interface VerificationData { signer_id: string; body: BodyData; trust: Trust }
export interface ProviderData { name: string; feature: string; compiled: boolean }
export interface StatusData {
  signer_id: string;
  pubkey_hex: string;
  secret_path: string;
  public_path: string;
  providers: ProviderData[];
}

/** May initialize identity; emits zero boot measurement and no hardware measurement. */
export function exportReport(): ReportData { return call(ATTESTATION_EXPORT, {}); }
/** Explicit trust, never the report's embedded key as authority. */
export function verify(reportPath: string, trust: Trust): VerificationData {
  return call(ATTESTATION_VERIFY, { report_path: reportPath, trust });
}
/** May initialize identity. Paths describe storage, not signing authority. */
export function status(): StatusData { return call(ATTESTATION_STATUS, {}); }
