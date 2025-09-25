# Releasing swain_cli

This runbook covers the end-to-end steps for shipping a tagged release that includes updated JRE assets and PyPI artifacts.

## Quick reference
- **Version bump locations**: `pyproject.toml`, `swain_cli/__init__.py`, and anywhere else the version is surfaced to users.
- **Cached assets**: Update embedded JRE checksums and the `ASSET_BASE` constant in `swain_cli/cli.py` whenever you move the downloads to a new release tag.
- **Release workflows**: `release.yml` handles JRE builds, distribution publishing, and optional PyInstaller binaries; `ci.yml` exercises pytest across platforms and Python 3.8/3.11.

### Release notes — v0.3.0
- Reworked authentication to capture tenant context, persist refresh tokens, and support fetching tenant account names for interactive flows.
- Added tenant-aware CRUD SQL helpers that automatically enforce the `/api` prefix and fetch dynamic swagger documents per connection.
- Tuned JVM defaults, including higher heap ceilings and explicit G1GC usage, to improve OpenAPI Generator stability on large schemas.
- Updated packaging metadata so asset bundles ship consistently via `MANIFEST.in` without obsolete JRE binaries.

### Release notes — v0.2.2
- Added credential-based authentication (`swain_cli auth login --credentials`) that stores both access and refresh tokens in the system keyring.
- Fixed the interactive project/connection picker so questionary no longer crashes when rendering choices.
- Bumped the default release assets to `v0.2.2` and refreshed packaging/tests prior to publish.

## 1. Pre-release checklist
- Confirm `main` contains the changes you intend to release and that `plan.md` or changelog notes are up to date.
- Run the full test suite locally: `python -m pytest`.
- Verify the runtime dependency list in `pyproject.toml` matches the CLI implementation (Typer/httpx/questionary/platformdirs/keyring/pooch) and update release notes accordingly.
- Update the version number where required and commit the result (for example, `"Release v0.x.y"`).
- If the JRE archives changed, record new SHA-256 values in `swain_cli/cli.py` and verify the filenames match the release assets.
- Smoke-test the CLI locally using both the embedded and system engines if possible:
  ```bash
  swain_cli engine install-jre
  swain_cli doctor
  swain_cli gen -i ./examples/petstore.yaml -l python -o ./tmp-sdks
  swain_cli gen -i ./examples/petstore.yaml -l python -o ./tmp-sdks --engine system
  ```

## 2. Produce JRE archives (only when needed)
1. Trigger the `build-jre` workflow via the GitHub Actions UI.
2. Provide the desired Temurin version and an optional `release_tag` (`jre-<version>`). The workflow runs the platform-specific scripts in `scripts/` to build trimmed JREs.
3. When the workflow finishes, download the `.sha256` files from the logs/artifacts and paste the sums into `swain_cli/cli.py`.
4. If you skipped the optional `release_tag`, upload the produced archives and checksums manually to the appropriate GitHub release.

## 3. Tag the release
```bash
# After committing the version bump and checksum updates
git push origin main
git tag v0.x.y
git push origin v0.x.y
```

Pushing the tag triggers the `release` workflow automatically.

## 4. GitHub Actions workflows
- **`release.yml`**
  1. `build-jres` matrix builds the trimmed JRE archives for Linux (x86_64/arm64), macOS (Intel/Apple Silicon), and Windows. Each archive and companion `.sha256` file is uploaded to the GitHub Release for the tag.
  2. `publish` waits for `build-jres`, then runs `python -m build` and uploads the sdist/wheel to PyPI using `PYPI_API_TOKEN`.
  3. `binaries` (optional) runs PyInstaller on Linux/macOS/Windows and attaches the executables to the release.
- **`ci.yml`** runs on every push/PR to ensure the test suite passes. Confirm the latest PR before tagging is green.

## 5. Verify the release
1. Wait for the `release` workflow to succeed.
2. Check the tagged GitHub Release page and confirm all JRE archives plus `.sha256` files exist.
3. Optionally download an archive (for example `swain_cli-jre-linux-x86_64.tar.gz`) and verify its checksum locally.
4. Install the published package from PyPI in a clean environment (e.g. `pipx install swain_cli`) and run a quick smoke test with `swain_cli doctor` and `swain_cli list-generators`.
5. Update `plan.md` with release notes or status.

## 6. Troubleshooting
- **Matrix failures**: Re-run the failing job from the Actions UI; Linux ARM64 uses `uraimo/run-on-arch-action` and may flake occasionally.
- **PyPI upload issues**: Ensure `PYPI_API_TOKEN` is valid, assigned to the project, and stored as an Actions secret.
- **Windows packaging quirks**: Download the Temurin JDK manually and execute `scripts/build-jre-windows.ps1` via PowerShell to reproduce locally.
- **Stale caches**: If the embedded JRE changes between releases, warn users to reinstall via `swain_cli engine install-jre` or remove the cache directory printed by `swain_cli doctor`.

## 7. After the release
- Announce the release (for example in project channels or release notes).
- Close or update any GitHub issues tied to the milestone.
- Archive temporary artifacts (local `tmp-sdks`, downloaded JRE archives) to keep the workspace clean.
