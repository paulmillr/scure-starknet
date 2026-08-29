# Changelog for scure-starknet

## 2.4.0 (2026-08-29)

Upgrade noble-hashes and noble-curves to 2.4.0

## 2.3.0 (2026-08-08)

Improve error messages and type checks. Upgrade noble-hashes and noble-curves to 2.3.0

## 2.2.0 (2026-04-21)

* **April 2026 self-audit** (all files): no major issues found
  * Audited for spec compliance and security
* Fix all Byte Array types, to ensure proper work in both TypeScript 5.6 & TypeScript 5.9+
  * TS 5.6 has `Uint8Array`, while TS 5.9+ made it generic `Uint8Array<ArrayBuffer>`
  * This creates incompatibility of code between versions
  * Previously, it was hard to use and constantly emitted errors similar to `TS2345`
  * See [typescript#62240](https://github.com/microsoft/TypeScript/issues/62240) for more context
* Fix compilation issues on TypeScript v6
* Improve tree-shaking, reduce bundle sizes

*(We're skipping v2.1, to align with other noble / scure packages)*

## 2.0.0 (2025-08-25)

- The package is now ESM-only. ESM can finally be loaded from common.js on node v20.19+
    - Node v20.19 is now the minimum required version
    - Package imports now work correctly in bundler-less environments, such as browsers
    - Reduces npm package size (traffic consumed)
    - Reduces unpacked npm size (on-disk space)
- Upgrade to noble v2

## 1.1.2 (2025-05-29)

Update noble-hashes to v1.8 and noble-curves to v1.9

## 1.1.1 (2025-01-19)

- Update noble-hashes to v1.7 and noble-curves to v1.8
- Improve typescript types
- Publish to JSR.io

## 1.1.0 (2024-11-23)

* Upgrade dependencies
* feat: export `normalizePrivateKey` by @SergeyVolynkin in https://github.com/paulmillr/scure-starknet/pull/10

### New Contributors
* @thiagodeev made their first contribution in https://github.com/paulmillr/scure-starknet/pull/8
* @SergeyVolynkin made their first contribution in https://github.com/paulmillr/scure-starknet/pull/11

## 1.0.0 (2023-12-13)

- update noble-hashes to [1.3.3](https://github.com/paulmillr/noble-hashes/releases/tag/1.3.3)
- update noble-curves to [1.3.0](https://github.com/paulmillr/noble-curves/releases/tag/1.3.0)

## 0.1.0 (2022-11-23)

- Initial release
