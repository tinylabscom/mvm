Only the Sigstore bundle lives here: the published `runtime/go@1.0.0` bundle signed
under the former `mvm-templates` main-branch workflow identity (as served by
`tinylabscom/mvm-packs` main, commit `1d0ecbefbd1babb3021753badc1e76a06fd7a112`).
It signs the same manifest as `../signed-registry-go/manifest.json`. It exists
only so mvm-core can test the legacy identity's cutoff with an injected time.
