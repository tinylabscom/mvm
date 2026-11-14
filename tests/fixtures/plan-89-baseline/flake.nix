{
  description = "Plan 89 W1 baseline fixture — minimal flake used by scripts/plan-89-baseline.sh to trigger a builder VM cold boot. The harness measures boot fan-out (init_start_ms through job_start_ms), which mvm-host-vm-init writes to /job/boot-timings.json BEFORE exec'ing cmd.sh. So the flake itself doesn't need to produce a valid mvmctl build output — it just needs to exist as a syntactically valid flake at a path mvmctl will dispatch into the builder VM. The harness reads boot-timings.json regardless of whether the inner `nix build` succeeded, exactly because nothing we measure happens after job_start_ms.";

  # Deliberately no inputs — we don't want to fetch nixpkgs or
  # microvm.nix. Any input adds cold-cache download time on the first
  # run that has nothing to do with what the boot-timing baseline measures.

  outputs = _: {
    # Throw at evaluation time. nix-build inside the builder VM will
    # fail fast with this message; mvmctl will report build failure.
    # The harness inspects boot-timings.json (always written by
    # builder-init before cmd.sh runs) and ignores the build exit
    # code. That keeps the fixture down to zero dependencies and the
    # measurement isolated to the boot fan-out the plan cares about.
    packages.aarch64-linux.default = throw
      "plan-89-w1-baseline fixture: intentionally fails evaluation. The harness in scripts/plan-89-baseline.sh reads boot-timings.json from the job dir regardless of build outcome — see flake description for rationale.";
    packages.x86_64-linux.default = throw
      "plan-89-w1-baseline fixture: intentionally fails evaluation. The harness in scripts/plan-89-baseline.sh reads boot-timings.json from the job dir regardless of build outcome — see flake description for rationale.";
  };
}
