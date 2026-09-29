# Egress injection modes beyond the header (PS-02, #3712)

## What landed

A binding's secret could only be substituted into a request header. A
credential an API expects elsewhere — a query parameter, a URL path
segment, a Basic credential — had no honest shape: the operator either
abandoned the endpoint or asked the guest to handle the raw value.

- `SecretRef.inject: InjectionMode` (default `header`, skipped in
  serialization so old plans stay byte-identical) declares where the
  binding substitutes the placeholder: `header`, `query_param`,
  `url_path`, or `basic_auth` (the last requires `auth_type = basic`;
  the `InjectionMode::admits` predicate states the allowed pairs).
- `mvm-contract::substitution::position` parses where in a request a
  placeholder actually sits: header value, `Authorization: Basic`
  credential, path segment, query value/parameter-name, authority,
  fragment, or a part no mode covers.
- `prepare_request` walks headers and URL against both: a placeholder
  substituted where its binding does not declare is refused before
  anything is forwarded (`PrepareError::PlaceholderOutOfPosition`, mapped
  to a fail-closed `ProxyError::Refused` at the endpoint), and a
  `basic_auth` placeholder is decoded from the Basic credential,
  substituted, and re-encoded. Path and query values are
  percent-encoded on the wire.
- `SubstitutionDriver` grows `inject_mode`; the keyholder's
  `NetworkEndpoint` answers it from the resolved binding, so the wire
  decision and the declaration come from one place. A response echoing
  an encoded form is still scrubbed through the existing
  `reflect`-recording path.

Per-destination placeholders were already the only shape (one
placeholder per binding, refused and audited anywhere else); this
change only widens where a bound placeholder may sit.

## Tests

- 24 `mvm-contract` substitution tests: position classification for
  every URL part, mode/position agreement, percent-encoding, Basic
  decode/substitute/re-encode, signing-URL substitution, and the
  out-of-position refusals.
- 32 hostd keyholder/injection tests, including the leak gate
  (3 scenarios) now also covering a query-param reflection.
