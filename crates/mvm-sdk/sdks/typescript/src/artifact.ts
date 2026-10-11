/** Published host-local artifacts; IDs are not arbitrary filesystem paths. */
import { call } from "./_hostlib.js";
import { ARTIFACT_CONFIGURE_FIRECRACKER, ARTIFACT_INSPECT, ARTIFACT_VALIDATE } from "./hostabi/methods.js";

export function inspect(id: string): Record<string, unknown> {
  return call(ARTIFACT_INSPECT, { id });
}
export function validate(id: string): Record<string, unknown> {
  return call(ARTIFACT_VALIDATE, { id });
}
export function configureFirecracker(id: string): Record<string, unknown> {
  return call(ARTIFACT_CONFIGURE_FIRECRACKER, { id });
}
