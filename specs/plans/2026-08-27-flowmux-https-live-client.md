# FlowMux HTTPS live-client repair

Issue: #2930

The forward proxy must continue refusing an absolute-form `https://` request:
forwarding that head would send plaintext to a TLS port. The live product
witnesses instead need a client that opens an HTTP `CONNECT` tunnel before the
TLS handshake.

- [x] Replace every affected live HTTPS command with a pinned, multi-arch curl
      image and preserve the original allow/deny assertions.
- [x] Add a repository regression that rejects BusyBox `wget` on these HTTPS
      witnesses and requires the pinned CONNECT-capable client.
- [x] Run the focused regression, conformance listing, workspace check/tests,
      and Clippy.
- [x] Record the completed closeout in the sprint and refactor rollup.
- [ ] Merge the PR through the queue so issue #2930 closes from the landed fix.
