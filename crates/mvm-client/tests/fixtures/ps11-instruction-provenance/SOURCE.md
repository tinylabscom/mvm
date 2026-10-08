# PS-11 keyless instruction fixture

`PS11.instructions.md` is an immutable copy of `.cursor/rules/graft.mdc` at
commit `3793cea0a12edf81bb22dc67a820cbcac2d4d541`. The witness uses the real
GitHub Actions keyless Sigstore bundle produced alongside those exact bytes:

- workflow: `.github/workflows/sign-instructions.yml`
- run: <https://github.com/tinylabscom/mvm/actions/runs/37630921781/attempts/1>
- source commit: `3793cea0a12edf81bb22dc67a820cbcac2d4d541`
- issuer: `https://token.actions.githubusercontent.com`
- signer identity:
  `https://github.com/tinylabscom/mvm/.github/workflows/sign-instructions.yml@refs/heads/main`

The fixture uses a non-default filename. Tests select it with the explicit
include `**/PS11.instructions.md`, so ordinary instruction discovery does not
load it and future edits to root instruction files cannot stale this bundle.

