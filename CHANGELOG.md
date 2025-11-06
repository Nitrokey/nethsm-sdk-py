# Changelog

## Unreleased

-

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v2.0.1...HEAD)

## [v2.0.1](https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v2.0.1) (2025-11-06)

- Add support for unauthenticated shutdown.

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v2.0.0...v2.0.1)

## [v2.0.0](https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v2.0.0) (2025-10-15)

### Breaking Changes

- Remove `KeyType.EC_P224`
- Change arguments for `NetHSM.csr` and `NetHSM.key_csr`:
  - Require `common_name` argument
  - Require using keywords for all arguments (except for `key_id`)

### Features

- Add new enum values (requires NetHSM v3.0):
  - `KeyType`: `EC_P256K1`, `BrainpoolP256`, `BrainpoolP384`, `BrainpoolP512`
  - `KeyMechanism`: `BIP340_Signature`
  - `SignMode`: `BIP340`
  - `TlsKeyType`: `BrainpoolP256`, `BrainpoolP384`, `BrainpoolP512`
- Add support for dots, dashes and underscores in user and key IDs (requires NetHSM v3.0)
- Add `NetHSM.move_key` function for changing key IDs (requires NetHSM v3.0)
- Add optional `subject_alt_names` argument for `NetHSM.csr` and `NetHSM.key_csr` (requires NetHSM v3.0)
- Add optional `prefix` argument for `NetHSM.list_keys` (requires NetHSM v3.0)
- Always show the message returned by the NetHSM as part of the error message

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v1.4.1...v2.0.0)

## [v1.4.1](https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v1.4.1) (2025-06-05)

- Relax `urllib3` version requirement to `>= 2, <3`

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v1.4.0...v1.4.1)

## [v1.4.0](https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v1.4.0) (2025-04-25)

- Add support for custom CA certificates

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v1.3.0...v1.4.0)

## [v1.3.0](https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v1.3.0) (2025-03-13)

### Features

- Add TPM attestation keys and platform configuration registers to `SystemInfo` ([#128](https://github.com/Nitrokey/nethsm-sdk-py/pull/128))

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v1.2.1...v1.3.0)

## [v1.2.1](https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v1.2.1) (2024-07-31)

### Bugfixes

- Fix authentication for partial restore, i.e. on an operational instance ([#124](https://github.com/Nitrokey/nethsm-sdk-py/pull/124))

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v1.2.0...v1.2.1)

## [v1.2.0](https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v1.2.0) (2024-07-16)

### Features

- Add support for namespaces ([#110](https://github.com/Nitrokey/nethsm-sdk-py/pull/110))

### Bugfixes

- Fix authentication for partial restore, i. e. on an operational instance ([#120](https://github.com/Nitrokey/nethsm-sdk-py/pull/120))

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v1.1.0...v1.2.0)

## [v1.1.0][] (2024-05-03)

[v1.1.0]: https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v1.1.0

### Features

- Support key import from PEM files ([#99](https://github.com/Nitrokey/nethsm-sdk-py/issues/99))
- Add `ignore_whitespace` option to `Base64.from_encoded` ([#108](https://github.com/Nitrokey/nethsm-sdk-py/issues/108))

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v1.0.0...v1.1.0)

## [v1.0.0][] (2023-11-27)

[v1.0.0]: https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v1.0.0

This release defines the stable API for the SDK based on the NetHSM
[v1.0](nethsm-v1.0) release.  It also improves the handling of base64-encoded
data and simplifies the provision and restore methods.

[nethsm-v1.0]: https://github.com/Nitrokey/nethsm/releases/tag/v1.0

### Breaking Changes

- Introduce custom type for Base64-encoded data by @robin-nitrokey ([#104](https://github.com/Nitrokey/nethsm-sdk-py/pull/104))

### Other Changes

- Make system time optional in provision and restore by @robin-nitrokey ([#105](https://github.com/Nitrokey/nethsm-sdk-py/pull/105))

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v0.5.0...v1.0.0)

## [v0.5.0][] (2023-11-23)

[v0.5.0]: https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v0.5.0

This release updates the API specification and improves the Python API.

### Changes

- NetHSM API changes
  - Adjust to /keys/{KeyID}/cert only one MIME type API change. by @q-nk ([#60](https://github.com/Nitrokey/nethsm-sdk-py/pull/60))
  - Incorporate API specification changes on /keys/{KeyID}/cert type. by @q-nk ([#62](https://github.com/Nitrokey/nethsm-sdk-py/pull/62))
  - Use generated client for set_key_certificate by @robin-nitrokey ([#64](https://github.com/Nitrokey/nethsm-sdk-py/pull/64))
  - Fix return type for get_key_certificate by @robin-nitrokey ([#66](https://github.com/Nitrokey/nethsm-sdk-py/pull/66))
  - Update OpenAPI generator and remove schema patches by @robin-nitrokey ([#55](https://github.com/Nitrokey/nethsm-sdk-py/pull/55))
  - Adjust system restore code to system restore multipart api by @q-nk ([#73](https://github.com/Nitrokey/nethsm-sdk-py/pull/73))
  - Pass old passphrase when setting unlock or backup passphrase by @robin-nitrokey ([#72](https://github.com/Nitrokey/nethsm-sdk-py/pull/72))
  - Update API spec by @robin-nitrokey ([#98](https://github.com/Nitrokey/nethsm-sdk-py/pull/98))
- Python API refinements
  - Use lazy imports for generated client by @robin-nitrokey ([#67](https://github.com/Nitrokey/nethsm-sdk-py/pull/67))
  - Support different types of bytes input by @robin-nitrokey ([#82](https://github.com/Nitrokey/nethsm-sdk-py/pull/82))
  - Use enums instead of literals by @robin-nitrokey ([#81](https://github.com/Nitrokey/nethsm-sdk-py/pull/81))
  - Test enum completeness by @robin-nitrokey ([#84](https://github.com/Nitrokey/nethsm-sdk-py/pull/84))
  - Return dataclasses from get_info and encrypt by @robin-nitrokey ([#85](https://github.com/Nitrokey/nethsm-sdk-py/pull/85))
  - Mark helpers with underscore prefix by @robin-nitrokey ([#87](https://github.com/Nitrokey/nethsm-sdk-py/pull/87))
  - Refactor get_key and Key by @robin-nitrokey ([#89](https://github.com/Nitrokey/nethsm-sdk-py/pull/89))
  - Use dataclasses for add_key by @robin-nitrokey ([#91](https://github.com/Nitrokey/nethsm-sdk-py/pull/91))
  - Always use API version from API spec by @robin-nitrokey ([#92](https://github.com/Nitrokey/nethsm-sdk-py/pull/92))
  - Make authentication optional by @robin-nitrokey ([#94](https://github.com/Nitrokey/nethsm-sdk-py/pull/94))
  - Parse system time into datetime object by @robin-nitrokey ([#95](https://github.com/Nitrokey/nethsm-sdk-py/pull/95))
  - Fix type annotations for add_key by @robin-nitrokey ([#101](https://github.com/Nitrokey/nethsm-sdk-py/pull/101))

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v0.4.0...v0.5.0)

## [v0.4.0][] (2023-10-27)

[v0.4.0]: https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v0.4.0

This release updates the API specification and adds support for validating
backup files.

### Changes

- Fix and extend typing checks
  - [#35](https://github.com/Nitrokey/nethsm-sdk-py/pull/35): fix: type error whith mime_type (@nponsard)
  - [#42](https://github.com/Nitrokey/nethsm-sdk-py/pull/42): Update OpenAPI client and extend mypy checks (@robin-nitrokey)
  - [44](https://github.com/Nitrokey/nethsm-sdk-py/pull/44): Enable strict mypy checks for nethsm module (@robin-nitrokey)
- Improve tests
  - [#37](https://github.com/Nitrokey/nethsm-sdk-py/pull/37): Allow a time delta in the time test (@q-nk)
  - [#51](https://github.com/Nitrokey/nethsm-sdk-py/pull/51): Extend backup/restore tests (@robin-nitrokey)
- Adapt to API changes
  - [#41](https://github.com/Nitrokey/nethsm-sdk-py/pull/41): Removed double Content-Type workaround (@q-nk)
  - [#43](https://github.com/Nitrokey/nethsm-sdk-py/pull/43): Adjust API delete certificate error message & status code (@q-nk)
- [#47](https://github.com/Nitrokey/nethsm-sdk-py/pull/47): Add certifi dependency (@robin-nitrokey)
- [#52](https://github.com/Nitrokey/nethsm-sdk-py/pull/52): Add backup validation (@robin-nitrokey)

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v0.3.2...v0.4.0)

## [v0.3.2][] (2023-09-29)

[v0.3.2]: https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v0.3.2

This release fixes a warning if TLS verification is disabled.

### Changes

- fix: disable warnings when tls verification is disabled by @nponsard ([#31](https://github.com/Nitrokey/nethsm-sdk-py/pull/31))

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v0.3.1...v0.3.2)

## [v0.3.1][] (2023-09-29)

[v0.3.1]: https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v0.3.1

This release fixes the exception data.

### Changes

- fix: exception data by @nponsard ([#30](https://github.com/Nitrokey/nethsm-sdk-py/pull/30))

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v0.3.0...v0.3.1)

## [v0.3.0][] (2023-09-29)

[v0.3.0]: https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v0.3.0

This release improves the exception handling.

### Changes

- refactor: exception handling by @nponsard ([#27](https://github.com/Nitrokey/nethsm-sdk-py/pull/27))

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v0.2.0...v0.3.0)

## [v0.2.0][] (2023-09-28)

[v0.2.0]: https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v0.2.0

This release improves the documentation, removes an unused dependency and
updates the API specification.

### Changes

- doc: document lib usage by @nponsard ([#11](https://github.com/Nitrokey/nethsm-sdk-py/pull/11))
- fix: remove request dependency by @nponsard ([#12](https://github.com/Nitrokey/nethsm-sdk-py/pull/12))
- feat: update api spec with format: binary by @nponsard ([#19](https://github.com/Nitrokey/nethsm-sdk-py/pull/19))
- doc: document update() workaround by @nponsard ([#20](https://github.com/Nitrokey/nethsm-sdk-py/pull/20))

[All Changes](https://github.com/Nitrokey/nethsm-sdk-py/compare/v0.1.0...v0.2.0)

## [v0.1.0][] (2023-09-26)

[v0.1.0]: https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v0.1.0

Initial release.
