# Pure-Nix evaluation tests for mkGuest. Run via:
#
#   cd nix && nix --extra-experimental-features 'nix-command flakes' \
#     eval --file tests/mk-guest-eval.nix
#
# Validates the user-facing surface of `lib.<system>.mkGuest` without
# actually building anything (no kernel compile, no rootfs). Fast
# enough to run on every PR; the corresponding Rust test in
# `tests/nix_flake_structure.rs` shells out to this file when nix is
# on PATH (gated; skipped otherwise).

let
  flake = builtins.getFlake (toString ./..);
  system = "x86_64-linux";
  pkgs = import flake.inputs.nixpkgs { inherit system; };
  mkGuest = flake.lib.${system}.mkGuest;

  # ── 1. shell entrypoint → accessible mode inferred ────────────
  shellGuest = mkGuest {
    name = "shell-test";
    entrypoint.shell = "/bin/bash";
  };

  # ── 2. command entrypoint → sealed mode inferred ──────────────
  commandGuest = mkGuest {
    name = "command-test";
    entrypoint.command = [ "/usr/local/bin/serve" ];
  };

  # ── 3. services entrypoint → sealed mode inferred ─────────────
  servicesGuest = mkGuest {
    name = "services-test";
    entrypoint.services = {
      web = { command = [ "/bin/web" ]; };
      worker = { command = [ "/bin/worker" ]; };
    };
  };

  # ── 4. shell + dev=false → user override sealed ───────────────
  shellSealedGuest = mkGuest {
    name = "shell-sealed-test";
    entrypoint.shell = "/bin/bash";
    dev = false;
  };

  # ── 5. command + dev=true → user override accessible ──────────
  commandAccessibleGuest = mkGuest {
    name = "command-accessible-test";
    entrypoint.command = [ "/bin/x" ];
    dev = true;
  };

  meta = drv: drv.passthru.mvm;
  rejects = expr:
    let
      attempted = builtins.tryEval (builtins.deepSeq expr true);
    in
    attempted.success == false;
in
{
  shell_default_accessible = (meta shellGuest).accessible == true
    && (meta shellGuest).sealed == false
    && (meta shellGuest).entrypointKind == "shell";

  command_default_sealed = (meta commandGuest).accessible == false
    && (meta commandGuest).sealed == true
    && (meta commandGuest).entrypointKind == "command";

  services_default_sealed = (meta servicesGuest).accessible == false
    && (meta servicesGuest).sealed == true
    && (meta servicesGuest).entrypointKind == "services";

  shell_with_dev_false_is_sealed = (meta shellSealedGuest).accessible == false
    && (meta shellSealedGuest).sealed == true;

  command_with_dev_true_is_accessible = (meta commandAccessibleGuest).accessible == true
    && (meta commandAccessibleGuest).sealed == false;

  # Name + hypervisor metadata propagation
  metadata_propagates = (meta shellGuest).name == "shell-test"
    && (meta shellGuest).hypervisor == "firecracker";

  # ── busybox-as-PID-1 invariants ───────────────────────────────
  #
  # The boot-time budget pins the init system. Asserting it here so a
  # future change that swaps back to NixOS+systemd (e.g., because it's
  # "easier") fails this gate before merge.
  init_system_is_busybox = (meta shellGuest).initSystem == "busybox";

  # Floor: every backend ≤ 300 ms cold p50. The metadata surfaces the
  # budget on every derivation; CI's xtask perf enforces. Guarding it
  # here so a future change can't silently regress the floor.
  boot_budget_firecracker_is_300ms =
    (meta shellGuest).expectedBootMs == 300;

  libkrun_boot_budget_is_300ms =
    let
      msbGuest = mkGuest {
        name = "msb-budget";
        entrypoint.command = [ "/bin/x" ];
        hypervisor = "libkrun";
      };
    in
    (meta msbGuest).expectedBootMs == 300;

  # ── Privilege model invariants (rootless) ─────────────────────
  #
  # Defaults: dev image runs entrypoint as root (debug-friendly
  # shell); prod image runs entrypoint as uid 1000 (rootless
  # workload, defense in depth); agent always uid 990.

  dev_default_entrypoint_is_root = (meta shellGuest).uids.entrypoint == 0
    && (meta shellGuest).rootlessEntrypoint == false;

  prod_default_entrypoint_is_rootless = (meta commandGuest).uids.entrypoint == 1000
    && (meta commandGuest).rootlessEntrypoint == true;

  agent_uid_is_always_990_by_default = (meta shellGuest).uids.agent == 990
    && (meta commandGuest).uids.agent == 990
    && (meta servicesGuest).uids.agent == 990;

  # ── Override path (uids = { ... } argument) ───────────────────

  rootless_interactive_via_uids_override =
    let
      g = mkGuest {
        name = "rootless-dev";
        entrypoint.shell = "/bin/sh";
        uids = { entrypoint = 1000; agent = 990; };
      };
    in
    (meta g).rootlessEntrypoint == true
    && (meta g).accessible == true   # still dev mode
    && (meta g).uids.entrypoint == 1000;

  rootful_prod_via_uids_override =
    let
      g = mkGuest {
        name = "rootful-prod";
        entrypoint.command = [ "/bin/x" ];
        uids = { entrypoint = 0; };
      };
    in
    (meta g).rootlessEntrypoint == false
    && (meta g).sealed == true
    && (meta g).uids.entrypoint == 0;

  custom_agent_uid_round_trips =
    let
      g = mkGuest {
        name = "custom-agent";
        entrypoint.command = [ "/bin/x" ];
        uids = { agent = 5000; };
      };
    in
    (meta g).uids.agent == 5000
    && (meta g).uids.entrypoint == 1000;  # default unaffected

  builder_uid_round_trips =
    let
      g = mkGuest {
        name = "builder-uid";
        entrypoint.shell = "/bin/sh";
        builderUid = 902;
      };
    in
    (meta g).builderUid == 902;

  # ── Agent supervision invariants ─────────────────────────────
  #
  # Every mkGuest output advertises whether the bundled
  # mvm-guest-agent is the stub or the real binary. The agent is now
  # the cross-compiled Rust binary, so every mkGuest output reports
  # "real". A future production lint can fail any deployment whose
  # `passthru.mvm.agentBinary` is not "real".

  agent_binary_is_real = (meta shellGuest).agentBinary == "real"
    && (meta commandGuest).agentBinary == "real"
    && (meta servicesGuest).agentBinary == "real";

  # ── Privilege-drop binary provenance ─────────────────────────
  #
  # The generated init must use the dedicated static-musl helper rather than
  # busybox's reduced applet or the much larger util-linux package.
  setpriv_is_custom_static_musl =
    (meta shellGuest).setprivHelperName == "mvm-setpriv"
    && (meta commandGuest).setprivHelperName == "mvm-setpriv";

  # ── Runtime overlay awareness ─────────────────────────────────
  #
  # Every image built by mkGuest must advertise that its rootfs
  # carries the `/mvm/runtime` bind-mount target and that the
  # init script prefers the overlay-provided agent. A future change
  # that drops the overlay-aware code path (e.g. reverting the
  # /init agent-resolution block) flips this metadata to `false`
  # before the boot regression surfaces, giving CI a tight signal
  # for the load-bearing invariant.

  overlay_aware_metadata_set_on_shell = (meta shellGuest).overlayAware == true;
  overlay_aware_metadata_set_on_command = (meta commandGuest).overlayAware == true;
  overlay_aware_metadata_set_on_services = (meta servicesGuest).overlayAware == true;

  # ── Dev console wiring ────────────────────────────────────────
  #
  # `withInteractive` is the console-wiring fact. The agent binary is
  # universal; runtime profile and signed-grant checks enforce DevOnly
  # requests. These assert the surfaced image metadata tracks the entrypoint
  # classification and its dev/sealed override.

  interactive_image_wires_console = (meta shellGuest).withInteractive == true
    && (meta shellGuest).accessible == true
    && (meta shellGuest).entrypointKind == "shell";

  sealed_command_image_has_no_console = (meta commandGuest).withInteractive == false
    && (meta commandGuest).sealed == true;

  # dev=true on a command entrypoint still wires the console
  dev_override_command_wires_console = (meta commandAccessibleGuest).withInteractive == true;

  # dev=false on a shell entrypoint drops the console
  sealed_override_shell_has_no_console = (meta shellSealedGuest).withInteractive == false;

  # ── SSH ban invariants ────────────────────────────────────────
  #
  # mkGuest enforces the no-SSH-session boundary at evaluation time:
  # user templates cannot add openssh/dropbear/ssh
  # packages, SSH config paths, authorized_keys, known_hosts, or key
  # material through packages or extraFiles.

  normal_guest_reports_ssh_template_ban = (meta shellGuest).sshTemplateBan == true;

  openssh_package_is_rejected =
    rejects ((
      meta (mkGuest {
        name = "bad-openssh";
        entrypoint.command = [ "/bin/x" ];
        packages = [ pkgs.openssh ];
      })
    ).sshTemplateBan);

  ssh_extra_file_path_is_rejected =
    rejects ((
      meta (mkGuest {
        name = "bad-ssh-file";
        entrypoint.command = [ "/bin/x" ];
        extraFiles."/root/.ssh/authorized_keys".content = "ssh-ed25519 AAAA test";
      })
    ).sshTemplateBan);

  ssh_extra_file_content_is_rejected =
    rejects ((
      meta (mkGuest {
        name = "bad-ssh-content";
        entrypoint.command = [ "/bin/x" ];
        extraFiles."/etc/banner".content = "install openssh here";
      })
    ).sshTemplateBan);

  # ── declared-but-unenforced surface ───────────────────────────
  # `mvmctl generate template` emits `healthChecks` into its scaffolds and the
  # mkGuest guide teaches all three. Rejecting them made every scaffolded
  # project fail to evaluate with "unexpected argument". They are accepted and
  # recorded; nothing acts on them until the supervisor lands.

  health_checks_are_accepted =
    (meta (mkGuest {
      name = "hc";
      entrypoint.command = [ "/bin/x" ];
      healthChecks.app = { healthCmd = "true"; healthIntervalSecs = 5; };
    })).unenforced.names == [ "healthChecks" ];

  volume_mounts_are_accepted =
    (meta (mkGuest {
      name = "vm";
      entrypoint.command = [ "/bin/x" ];
      volumeMounts."/mnt/work" = { volume = "workspace"; readOnly = false; };
    })).unenforced.names == [ "volumeMounts" ];

  service_group_is_accepted =
    (meta (mkGuest {
      name = "sg";
      entrypoint.command = [ "/bin/x" ];
      serviceGroup = "web";
    })).unenforced.names == [ "serviceGroup" ];

  # A guest declaring none of them reports nothing, so the warning stays quiet
  # for the overwhelmingly common case.
  unenforced_is_empty_by_default =
    (meta (mkGuest {
      name = "plain";
      entrypoint.command = [ "/bin/x" ];
    })).unenforced.names == [ ];

  # The values themselves are carried through, not just their names — a host
  # or an audit can see exactly what the flake asked for and did not get.
  unenforced_records_the_declared_value =
    (meta (mkGuest {
      name = "hc-value";
      entrypoint.command = [ "/bin/x" ];
      healthChecks.app = { healthCmd = "/bin/true"; };
    })).unenforced.healthChecks.app.healthCmd == "/bin/true";

  # A typo is still an error — the argument set is deliberately non-variadic —
  # but `builtins.tryEval` cannot catch an arity error the way it catches a
  # `throw`, so that case is not expressible here. `wrong_shape_is_rejected`
  # below covers the shape guard, which is a real throw.

  wrong_shape_is_rejected =
    rejects (mkGuest {
      name = "bad-shape";
      entrypoint.command = [ "/bin/x" ];
      serviceGroup = 42;
    });
}
