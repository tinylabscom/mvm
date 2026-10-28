import { readFileSync } from "node:fs";
import { afterEach, expect, expectTypeOf, it } from "vitest";

import { checkpoint, type CheckpointListReply } from "../src/index.js";
import type { CheckpointListReply as GeneratedReply } from "../src/hostabi/host_abi.js";
import { setInvokeForTesting, type HostLibraryFailure } from "../src/_hostlib.js";
import { HostLibraryError, MachineBackendError } from "../src/_errors/types.js";

afterEach(() => setInvokeForTesting(null));

const hex = "a".repeat(64);
const digest = `sha256:${hex}`;
const pin = {
  bundle_sha256: hex, manifest_sig_base64: "A".repeat(86) + "==", key_id: "publisher",
};
const artifacts = {
  overlay_path: "/runtime/overlay",
  overlay_verity_path: "/runtime/overlay.verity",
  initramfs_path: "/runtime/initramfs",
  overlay_roothash: hex,
};
const minimal: CheckpointListReply[number] = {
  id: "cp-0", class: "fs_quick", vm_name: "vm", tag: null, parent: null,
  created_unix: 1, content: [{ name: "rootfs", sha256: hex }],
  supervisor_config_digest: hex, meta_digest: digest, audit_ref: null,
};
const complete: CheckpointListReply[number] = {
  ...minimal, id: "cp-1", class: "vm_full", tag: "saved", parent: digest,
  key_domain: "tenant:tenant-a", protection: "sealed_v1",
  runtime_overlay_version: "1.0.0",
  runtime_launch_binding: {
    runtime: "cli_assembly", ...artifacts,
    provenance: {
      kind: "release",
      proof: {
        archive: "/runtime/archive", checksum: "/runtime/checksum",
        signature_bundle: "/runtime/signature", archive_sha256: hex,
        version: "1.0.0", arch: "aarch64",
      },
    },
  },
  snapshot_id: digest,
  grants: {
    cpu: { unit: "share", millicores: 1500 },
    wall_clock: { kind: "secs", secs: 60 },
    egress: { allow: [{ host: "example.com", port: 443 }] },
    drive: {
      workspace_roots: ["/workspace"], program_id: "editor",
      max_bytes_in: 1024, max_bytes_out: 2048, ttl: 30,
    },
    display_input: {
      attended: true, clipboard: { max_paste_bytes: 1024 },
      human_credential: { destinations: [{ host: "example.com", port: 443 }] },
    },
    application_terminal: { argv: ["/usr/bin/application", "--interactive"] },
  },
  session: {
    session_id: "session-1", generation: 2, journal_cursor: 3,
    approval_head: digest, replay_input_digest: digest,
  },
  machine_input_cursor: 0, audit_ref: "audit-entry-1",
};
const reply: CheckpointListReply = [
  minimal,
  complete,
  {
    ...complete, id: "cp-10",
    runtime_launch_binding: {
      runtime: "cli_assembly", ...artifacts,
      provenance: { kind: "source", version: "dev", arch: "x86_64", archive_sha256: hex },
    },
    grants: {
      cpu: { unit: "fuel", instructions: 42 }, wall_clock: { kind: "unbounded" },
      egress: { allow: [] }, display_input: {},
    },
  },
  {
    ...complete, id: "cp-2",
    runtime_launch_binding: {
      runtime: "legacy_bundle", proof: { archive: "/bundle", pin },
      rootfs_path: "/rootfs", initramfs_path: null,
    },
    session: {
      session_id: "session-2", generation: 0, journal_cursor: 0, approval_head: digest,
    },
  },
  {
    ...complete, id: "cp-3",
    runtime_launch_binding: {
      runtime: "legacy_portable", ...artifacts,
      proof: { archive: "/portable", pin, manifest_sha256: hex, arch: "x86_64" },
      rootfs_path: "/rootfs", kernel_path: "/kernel", version: "legacy",
    },
    grants: {},
  },
];

it.each([{ reply: [] }, { reply }])(
  "preserves complete replies through a mocked native-call seam",
  ({ reply: value }) => {
    const calls: { method: string; body: string }[] = [];
    setInvokeForTesting((method, body) => {
      calls.push({ method, body: body.toString("utf8") });
      return [0, Buffer.from(JSON.stringify(value))];
    });
    const actual = checkpoint.list();
    expect(actual).toEqual(value);
    expect(actual.map((record) => record.id)).toEqual(value.map((record) => record.id).sort());
    expect(calls).toEqual([{ method: "checkpoint.list", body: "{}" }]);
  },
);

it("preserves the shared CLI/client/hostlib metadata fixture", () => {
  const wire = readFileSync(
    new URL("../../../../mvm-core/tests/fixtures/checkpoint-list.json", import.meta.url),
    "utf8",
  );
  setInvokeForTesting((method, body) => {
    expect(method).toBe("checkpoint.list");
    expect(body.toString("utf8")).toBe("{}");
    return [0, Buffer.from(wire)];
  });
  expect(checkpoint.list()).toEqual(JSON.parse(wire));
});

it("exports the no-argument wrapper with the generated reply type", () => {
  expectTypeOf(checkpoint.list).parameters.toEqualTypeOf<[]>();
  expectTypeOf(checkpoint.list).returns.toEqualTypeOf<GeneratedReply>();
  expectTypeOf<CheckpointListReply>().toEqualTypeOf<GeneratedReply>();
});

it("preserves typed backend errors", () => {
  setInvokeForTesting(() => [1, Buffer.from(JSON.stringify({
    code: "BACKEND_ERROR", message: "invalid checkpoint metadata", retryable: false,
  }))]);
  let failure: unknown;
  try {
    checkpoint.list();
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(HostLibraryError);
  expect(failure).toBeInstanceOf(MachineBackendError);
  expect((failure as MachineBackendError).message).toBe("invalid checkpoint metadata");
  expect((failure as HostLibraryFailure).code).toBe("BACKEND_ERROR");
  expect((failure as HostLibraryFailure).retryable).toBe(false);
});
