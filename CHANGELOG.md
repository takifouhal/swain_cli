# Changelog

## v0.3.12
- Prefer downloading per-connection swagger directly from the connection build endpoint, falling back to the Swain proxy when direct fetch fails (avoids truncated proxy responses).

## v0.3.11
- Fix Swain connection swagger downloads by targeting `GET /api/connections/:id/dynamic-swagger` (with a fallback to the legacy underscore route).

## v0.3.10
- Refresh macOS arm64 embedded JRE SHA-256 to match released asset; fixes hash mismatch on first-run download.

## v0.3.9
- Add fallback to CrudSQL/proxy base for Swain project/connection discovery when `/api/Project` returns 404; keeps interactive flows working behind `/crud` proxies.
- Regression tests updated for fallback behavior.

## v0.3.8
- Interactive auth now targets the CrudSQL (or proxied) base, matching `/crud/auth/*` deployments; improved `/crud` suffix normalization.
- Added regression tests to lock base URL inference.

## v0.3.7
- Differentiate Swain platform base from CrudSQL base; `--swain-base-url` now infers `/crud` for dynamic swagger while Swain discovery/auth stay on the platform host.
- Added explicit `--swain-base-url` to interactive/gen flows and updated tests.

## v0.3.6
- Default to `--skip-operation-example` (alongside docs/tests suppression) so OpenAPI Generator no longer runs out of memory when circular response schemas generate huge examples; interactive and scripted runs inherit this automatically.

## v0.3.5
- Pass an explicit `base_url` into `fetch_swain_connection_schema` so Swain connection schema downloads use the correct backend base URL; updated tests accordingly.

## v0.3.4
- Accept multiple checksum formats (bare hex, GNU/BSD, PowerShell table) when reading `.sha256` files on all platforms.
- Standardize Windows JRE `.sha256` files to `"<hex>  <filename>"` for cross-platform consistency.

## v0.3.3
- Fix embedded JRE download base to point at v0.3.2 assets (asset name alignment) so Windows/macOS/Linux first-run downloads succeed.
- Update installer examples to reference `v0.3.3`.

## v0.3.0
- Reworked authentication to capture tenant context, persist refresh tokens, and surface tenant names in interactive flows.
- Added tenant-aware CRUD SQL helpers that enforce the `/api` prefix and download dynamic swagger per connection.
- Tuned JVM defaults (higher heap ceilings, explicit G1GC) to stabilise OpenAPI Generator on large schemas.

## v0.2.2
- Added credential-based authentication (`swain_cli auth login --credentials`) that stores access and refresh tokens in the keyring.
- Fixed the interactive project/connection picker so questionary no longer crashes when rendering choices.
- Refreshed packaging/tests prior to publish.
