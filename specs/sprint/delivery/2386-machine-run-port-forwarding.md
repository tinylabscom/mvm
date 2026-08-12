# Machine run port forwarding

`machine run --port HOST:GUEST` now boots a persistent machine and owns
repeatable loopback-only forwards in the foreground, reusing the existing
`machine forward` lifecycle. Invalid mappings and detached ownership fail
before boot; parser, lifecycle-resolution, listener-bind, and hermetic BDD
coverage pin the contract; all 174 BDD scenarios pass.
