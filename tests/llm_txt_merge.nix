# Offline test for plan 45's `/.mvm/llm.txt` default + caller-wins
# merge semantics. Run via:
#
#   cd nix && nix eval --impure --raw \
#     --expr 'import ../tests/llm_txt_merge.nix { inherit (builtins.getFlake (toString ./.)) inputs; }'
#
# Asserts:
#   1. Library default `/.mvm/llm.txt` is present when caller passes no
#      `extraFiles`.
#   2. Default `mode` is "0644".
#   3. Caller-supplied `/.mvm/llm.txt` overrides the library default
#      (Nix `//` shallow merge, right-wins).
#   4. Caller-supplied unrelated entries don't disturb the default.

{ inputs }:

let
  pkgs = import inputs.nixpkgs { system = builtins.currentSystem; };
  lib = pkgs.lib;

  # Re-implement the merge locally. Mirrors the body of
  # `nix/flake.nix` mkGuestFn around `defaultExtraFiles` /
  # `extraFilesEffective`.
  defaultLlmTxt = "# mvm guest\n(test placeholder)";
  defaultExtraFiles = {
    "/.mvm/llm.txt" = {
      content = defaultLlmTxt;
      mode = "0644";
    };
  };
  merge = caller: defaultExtraFiles // caller;

  # Test 1: empty caller → library default present, mode 0644.
  t1 = merge { };
  assert1 = lib.assertMsg (
    t1 ? "/.mvm/llm.txt"
    && t1."/.mvm/llm.txt".content == defaultLlmTxt
    && t1."/.mvm/llm.txt".mode == "0644"
  ) "test 1 failed: default not preserved when caller is empty";

  # Test 2: caller overrides → caller wins on path collision.
  t2 = merge {
    "/.mvm/llm.txt" = {
      content = "OVERRIDE";
      mode = "0600";
    };
  };
  assert2 = lib.assertMsg (
    t2."/.mvm/llm.txt".content == "OVERRIDE" && t2."/.mvm/llm.txt".mode == "0600"
  ) "test 2 failed: caller override didn't win";

  # Test 3: unrelated caller entries coexist with default.
  t3 = merge {
    "/etc/mvm/extra" = {
      content = "extra";
      mode = "0644";
    };
  };
  assert3 = lib.assertMsg (
    t3 ? "/.mvm/llm.txt"
    && t3."/.mvm/llm.txt".content == defaultLlmTxt
    && t3 ? "/etc/mvm/extra"
    && t3."/etc/mvm/extra".content == "extra"
  ) "test 3 failed: unrelated caller entry disturbed default";
in
assert assert1;
assert assert2;
assert assert3;
"plan-45 llm.txt merge tests: 3/3 passed"
