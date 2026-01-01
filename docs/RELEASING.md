# Releasing swain_cli

This runbook walks through publishing a tagged release that ships refreshed JRE assets and updated PyPI distributions.

## Quick reference
- **Version bumps** — update `swain_cli/__init__.py` (packaging version is sourced from `__version__`) and any other user-facing version strings.
- **Embedded assets** — refresh JRE checksums (`JRE_ASSETS`) plus the `ASSET_BASE` constant in `swain_cli/constants.py` whenever download locations change.
- **Automation** — `release.yml` builds JREs, publishes to PyPI via Trusted Publishing (OIDC), and (optionally) creates PyInstaller binaries; `ci.yml` runs pytest across the supported Python versions on every push/PR.
- **Homebrew tap** — bump the version/URLs/checksums in `Formula/swain_cli.rb` so `brew upgrade` can pick up the release.

## End-to-end checklist
1. Confirm `main` has every change you intend to ship and that `CHANGELOG.md` (or your release notes source) is current.
2. Run the full test suite locally: `python -m pytest`.
3. Update the version in all required files and stage the changes.
4. Regenerate JRE artefacts and hashes if the Temurin version or layout changed.
5. Smoke-test both the embedded and system engines locally.
6. Commit with a message such as `Release vX.Y.Z` and tag the release.
7. Push the branch and tag to kick off the automation.

## Step-by-step guide
### 1. Prepare the release
- Review open PRs/issues and make sure nothing critical is missing.
- Verify runtime dependencies in `pyproject.toml` match what the CLI actually imports.
- Update release notes (`CHANGELOG.md`, GitHub Releases draft, or your chosen location).
- Run `python -m pytest` and fix failures before continuing.

### 2. Update embedded JRE assets (only when needed)
1. Launch the `build-jre` workflow from the GitHub Actions UI.
2. Supply the desired Temurin version and optional `release_tag` (typically `jre-<version>`). The workflow runs the scripts in `scripts/` to produce trimmed archives for Linux (x86_64 + arm64), macOS (Intel + Apple Silicon), and Windows.
3. When the workflow finishes, download the `.sha256` files from the run and paste the sums into `swain_cli/constants.py` (the `JRE_ASSETS` mapping).
4. Upload the new archives and checksum files to the release specified by `release_tag` (or manually to the appropriate release if you omitted it).

### 3. Finalise version bumps
- Ensure every version bump is committed (for example in `swain_cli/__init__.py`, CLI help text, and documentation).
- Update `Formula/swain_cli.rb` with the new version plus the per-platform download URLs + SHA-256 values once the PyInstaller binaries are uploaded.
- Stage the updated checksums and `ASSET_BASE` if assets moved.
- Commit with a message like `Release vX.Y.Z`.

### 4. Tag and push
```bash
git push origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```
Pushing the tag triggers `release.yml` automatically.

### 5. Workflow overview
- **`release.yml`**
  1. `build-jres` produces the trimmed JRE archives and uploads them (plus `.sha256` files) to the tagged GitHub Release.
  2. `publish` waits for JREs, runs `python -m build`, and uploads the wheel + sdist to PyPI using Trusted Publishing (`id-token: write`) and the `pypi` environment. The publish step uses `skip-existing: true` so re-runs won’t fail if the version is already uploaded.
  3. `binaries` (optional) builds PyInstaller executables for Linux, macOS, and Windows and attaches them to the release as:
     - `swain_cli-linux-x86_64`
     - `swain_cli-macos-x86_64`
     - `swain_cli-macos-arm64`
     - `swain_cli-windows-x86_64.exe`
- **`ci.yml`** runs on every push/PR; double-check the latest run before cutting the tag.

### 6. Configure Trusted Publishing (one-time)
Set this up once in PyPI, then all future tags publish automatically without secrets.

1. Go to PyPI → your project → Settings → Publishing → Add a trusted publisher.
2. Choose GitHub.
3. Repository: `takifouhal/swain_cli`.
4. Workflow filename: `.github/workflows/release.yml`.
5. Environment name: `pypi`.
6. In GitHub → repo → Settings → Environments, create an environment named `pypi` (no secrets required) and optionally add rules/approvals.
7. Save. The next run of `release.yml` can publish.

If a past run failed at “Publish to PyPI”, re-run that job from Actions after this setup.

### 7. Manual PyPI publish (fallback)
Use this only if the automated publish step fails or is skipped.
```bash
python3 -m build
python3 -m twine upload dist/swain_cli-<version>*
```
Export `TWINE_USERNAME=__token__` and `TWINE_PASSWORD=<pypi-token>` (or configure `~/.pypirc`) beforehand. Remove any stale files in `dist/`; PyPI rejects duplicates.

### 8. Verify the release
1. Wait for `release.yml` to succeed.
2. Inspect the tagged GitHub Release and confirm all JRE archives plus `.sha256` files are attached.
3. Optionally download an archive (e.g. `swain_cli-jre-linux-x86_64.tar.gz`) and verify the checksum locally.
4. Install the freshly published package in a clean environment either as a binary (no Python):
   - macOS/Linux: `curl -fsSL https://raw.githubusercontent.com/takifouhal/swain_cli/HEAD/scripts/install.sh | bash`
   - Windows (PowerShell): `iwr -useb https://raw.githubusercontent.com/takifouhal/swain_cli/HEAD/scripts/install.ps1 | iex`
   Or via Python: `pipx install swain_cli`.
   Then run `swain_cli doctor` and `swain_cli list-generators`.
5. Update `CHANGELOG.md` (or your release notes) with the final status.

### 9. After the release
- Announce the release (team channels, changelog, etc.).
- Close or update GitHub issues tied to the milestone.
- Clean up temporary artefacts such as local `tmp-sdks` directories or downloaded JRE archives.

## Troubleshooting
- **Matrix flakes** — rerun the failing job from the Actions UI; Linux ARM64 relies on `uraimo/run-on-arch-action` and occasionally flakes.
- **PyPI upload errors** — ensure the PyPI Trusted Publisher is configured for this repo and workflow. If needed, fall back to Twine with an API token.
- **Windows packaging quirks** — reproduce locally by downloading the Temurin JDK and running `scripts/build-jre-windows.ps1` in PowerShell.
- **Stale caches** — when the embedded JRE changes, remind users to run `swain_cli engine install-jre` or delete the cache path reported by `swain_cli doctor`.

## Historical release notes
### v0.3.10
- Refresh macOS arm64 embedded JRE SHA-256 to match released asset; fixes hash mismatch on first-run download.

### v0.3.9
- Add fallback to CrudSQL/proxy base for Swain project/connection discovery when `/api/Project` returns 404; keeps interactive flows working behind `/crud` proxies.
- Regression tests updated for fallback behavior.

### v0.3.8
- Interactive auth now targets the CrudSQL (or proxied) base, matching `/crud/auth/*` deployments; improved `/crud` suffix normalization.
- Added regression tests to lock base URL inference.

### v0.3.7
- Differentiate Swain platform base from CrudSQL base; `--swain-base-url` now infers `/crud` for dynamic swagger while Swain discovery/auth stay on the platform host.
- Added explicit `--swain-base-url` to interactive/gen flows and updated tests.

### v0.3.6
- Default to `--skip-operation-example` (alongside docs/tests suppression) so OpenAPI Generator no longer runs out of memory when circular response schemas generate huge examples; interactive and scripted runs inherit this automatically.

### v0.3.5
- Pass an explicit `base_url` into `fetch_swain_connection_schema` so Swain connection schema downloads use the correct backend base URL; updated tests accordingly.

### v0.3.4
- Accept multiple checksum formats (bare hex, GNU/BSD, PowerShell table) when reading `.sha256` files on all platforms.
- Standardize Windows JRE `.sha256` files to `"<hex>  <filename>"` for cross-platform consistency.

### v0.3.3
- Fix embedded JRE download base to point at v0.3.2 assets (asset name alignment) so Windows/macOS/Linux first-run downloads succeed.
- Update installer examples to reference `v0.3.3`.

### v0.3.0
- Reworked authentication to capture tenant context, persist refresh tokens, and surface tenant names in interactive flows.
- Added tenant-aware CRUD SQL helpers that enforce the `/api` prefix and download dynamic swagger per connection.
- Tuned JVM defaults (higher heap ceilings, explicit G1GC) to stabilise OpenAPI Generator on large schemas.
- Updated packaging metadata so bundles ship consistently via `MANIFEST.in` without obsolete JRE binaries.

### v0.2.2
- Added credential-based authentication (`swain_cli auth login --credentials`) that stores access and refresh tokens in the keyring.
- Fixed the interactive project/connection picker so questionary no longer crashes when rendering choices.
- Bumped default release assets to `v0.2.2` and refreshed packaging/tests prior to publish.
