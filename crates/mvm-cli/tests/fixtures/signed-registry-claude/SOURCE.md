This fixture is the published `agent/claude@1.0.1` policy pack from the
`mvm-packs` repository at commit `1d0ecbefbd1babb3021753badc1e76a06fd7a112`.
The manifest and profile are byte-for-byte copies. The Sigstore bundle JSON
has one terminal newline added; verification still checks the exact signed
manifest against the certificate and inclusion proof. The fixture is signed
under the former `mvm-templates` main-branch workflow identity, which the test
trusts explicitly. It is not presented as an official pack.
