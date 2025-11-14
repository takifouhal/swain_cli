# Releasing swain_cli

This runbook walks through publishing a tagged release that ships refreshed JRE assets and updated PyPI distributions.

## Quick reference
- **Version bumps** — update `pyproject.toml`, `swain_cli/__init__.py`, and any other user-facing version strings.
- **Embedded assets** — refresh JRE checksums plus the `ASSET_BASE` constant in `swain_cli/cli.py` whenever download locations change.
- **Automation** — `release.yml` builds JREs, publishes to PyPI, and (optionally) creates PyInstaller binaries; `ci.yml` runs pytest across Python 3.8–3.11 on every push/PR.

## End-to-end checklist
1. Confirm `main` has every change you intend to ship and that `plan.md` (or your changelog source) is current.
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
- Update release notes (`plan.md`, GitHub Releases draft, or your chosen location).
- Run `python -m pytest` and fix failures before continuing.

### 2. Update embedded JRE assets (only when needed)
1. Launch the `build-jre` workflow from the GitHub Actions UI.
2. Supply the desired Temurin version and optional `release_tag` (typically `jre-<version>`). The workflow runs the scripts in `scripts/` to produce trimmed archives for Linux (x86_64 + arm64), macOS (Intel + Apple Silicon), and Windows.
3. When the workflow finishes, download the `.sha256` files from the run and paste the sums into `swain_cli/cli.py`.
4. Upload the new archives and checksum files to the release specified by `release_tag` (or manually to the appropriate release if you omitted it).

### 3. Finalise version bumps
- Ensure every version bump is committed (for example in `pyproject.toml`, `swain_cli/__init__.py`, CLI help text, and documentation).
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
  2. `publish` waits for JREs, runs `python -m build`, and uploads the wheel + sdist to PyPI using `PYPI_API_TOKEN`.
  3. `binaries` (optional) builds PyInstaller executables for Linux, macOS, and Windows and attaches them to the release as:
     - `swain_cli-linux-x86_64`
     - `swain_cli-macos-x86_64`
     - `swain_cli-macos-arm64`
     - `swain_cli-windows-x86_64.exe`
- **`ci.yml`** runs on every push/PR; double-check the latest run before cutting the tag.

### 6. Manual PyPI publish (fallback)
Use this only if the automated publish step fails or is skipped.
```bash
python3 -m build
python3 -m twine upload dist/swain_cli-<version>*
```
Export `TWINE_USERNAME=__token__` and `TWINE_PASSWORD=<pypi-token>` (or configure `~/.pypirc`) beforehand. Remove any stale files in `dist/`; PyPI rejects duplicates.

### 7. Verify the release
1. Wait for `release.yml` to succeed.
2. Inspect the tagged GitHub Release and confirm all JRE archives plus `.sha256` files are attached.
3. Optionally download an archive (e.g. `swain_cli-jre-linux-x86_64.tar.gz`) and verify the checksum locally.
4. Install the freshly published package in a clean environment either as a binary (no Python):
   - macOS/Linux: `curl -fsSL https://raw.githubusercontent.com/takifouhal/swain_cli/HEAD/scripts/install.sh | bash`
   - Windows (PowerShell): `iwr -useb https://raw.githubusercontent.com/takifouhal/swain_cli/HEAD/scripts/install.ps1 | iex`
   Or via Python: `pipx install swain_cli`.
   Then run `swain_cli doctor` and `swain_cli list-generators`.
5. Update `plan.md` (or your release notes) with the final status.

### 8. After the release
- Announce the release (team channels, changelog, etc.).
- Close or update GitHub issues tied to the milestone.
- Clean up temporary artefacts such as local `tmp-sdks` directories or downloaded JRE archives.

## Troubleshooting
- **Matrix flakes** — rerun the failing job from the Actions UI; Linux ARM64 relies on `uraimo/run-on-arch-action` and occasionally flakes.
- **PyPI upload errors** — validate `PYPI_API_TOKEN`, ensure it has project access, and confirm the secret is present in repository settings.
- **Windows packaging quirks** — reproduce locally by downloading the Temurin JDK and running `scripts/build-jre-windows.ps1` in PowerShell.
- **Stale caches** — when the embedded JRE changes, remind users to run `swain_cli engine install-jre` or delete the cache path reported by `swain_cli doctor`.

## Historical release notes
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
