# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-tsa-v0.8.0...sigstore-tsa-v0.9.0) - 2026-06-17

### Other

- fail-closed if no root certs provided ([#114](https://github.com/sigstore/sigstore-rust/pull/114))
- Verify TSA response nonce ([#113](https://github.com/sigstore/sigstore-rust/pull/113))
- Make our use of jiff more idiomatic ([#100](https://github.com/sigstore/sigstore-rust/pull/100))

## [0.8.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-tsa-v0.7.0...sigstore-tsa-v0.8.0) - 2026-05-21

### Other

- Replace direct chrono usage with jiff ([#90](https://github.com/sigstore/sigstore-rust/pull/90))

## [0.7.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-tsa-v0.6.6...sigstore-tsa-v0.7.0) - 2026-05-13

### Added

- trust root update and dependency update ([#85](https://github.com/sigstore/sigstore-rust/pull/85))

## [0.6.6](https://github.com/sigstore/sigstore-rust/compare/sigstore-tsa-v0.6.5...sigstore-tsa-v0.6.6) - 2026-04-29

### Fixed

- *(sigstore-tsa)* honor SignerInfo digest algorithm in CMS verification ([#83](https://github.com/sigstore/sigstore-rust/pull/83))

## [0.6.4](https://github.com/sigstore/sigstore-rust/compare/sigstore-tsa-v0.6.3...sigstore-tsa-v0.6.4) - 2026-03-06

### Fixed

- nonce encoding to be minimal, use u64 explicitly ([#74](https://github.com/sigstore/sigstore-rust/pull/74))

### Other

- update rand requirement ([#64](https://github.com/sigstore/sigstore-rust/pull/64))

## [0.6.2](https://github.com/prefix-dev/sigstore-rust/compare/sigstore-tsa-v0.6.1...sigstore-tsa-v0.6.2) - 2026-02-04

### Other

- add native-tls feature, bump reqwest ([#51](https://github.com/prefix-dev/sigstore-rust/pull/51))

## [0.3.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-tsa-v0.2.0...sigstore-tsa-v0.3.0) - 2025-11-28

### Other

- remove more types
- remove certifactePem
- improve sign / verify flow, add conda specific test
- more cleanup of functions

## [0.2.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-tsa-v0.1.1...sigstore-tsa-v0.2.0) - 2025-11-27

### Other

- require trust root in constructor, remove more unused code, update readme
- remove duplicated types, add license and readme files

## [0.1.1](https://github.com/wolfv/sigstore-rust/compare/sigstore-tsa-v0.1.0...sigstore-tsa-v0.1.1) - 2025-11-27

### Other

- update Cargo.toml dependencies
