# Shared `unpackPhase` for recipes whose `src` is the mvm workspace.
#
# A `path:` input evaluated from the `nix/` subflake can retain a trailing
# `nix/..` source shape; the generic unpacker then fails with "destination
# already exists". Copying into a plain directory first sidesteps that, and
# keeps the workaround in one place rather than inline in every recipe.

{ mvmSrc }:

''
  runHook preUnpack
  cp -R ${mvmSrc}/. source
  chmod -R u+w source
  sourceRoot=source
  runHook postUnpack
''
