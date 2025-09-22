# Releasing swaggen

This runbook covers the end-to-end steps for shipping a tagged release that includes updated JRE assets and PyPI artifacts.

## Quick reference
- **Version bump locations**: `pyproject.toml`, `swaggen/__init__.py`, and anywhere else the version is surfaced to users.
- **Cached assets**: Update embedded JRE checksums in `swaggen/cli.py` when new archives are produced.
- **Release workflows**: `release.yml` handles JRE builds, distribution publishing, and optional PyInstaller binaries; `ci.yml` exercises pytest across platforms and Python 3.8/3.11.

## 1. Pre-release checklist
- Confirm `main` contains the changes you intend to release and that `plan.md` or changelog notes are up to date.
- Run the full test suite locally: `python -m pytest`.
- Update the version number where required and commit the result (for example, `"Release v0.x.y"`).
- If the JRE archives changed, record new SHA-256 values in `swaggen/cli.py` and verify the filenames match the release assets.
- Smoke-test the CLI locally using both the embedded and system engines if possible:
  ```bash
  swaggen engine install-jre
  swaggen doctor
  swaggen gen -i ./examples/petstore.yaml -l python -o ./tmp-sdks
  swaggen gen -i ./examples/petstore.yaml -l python -o ./tmp-sdks --engine system
  ```

## 2. Produce JRE archives (only when needed)
1. Trigger the `build-jre` workflow via the GitHub Actions UI.
2. Provide the desired Temurin version and an optional `release_tag` (`jre-<version>`). The workflow runs the platform-specific scripts in `scripts/` to build trimmed JREs.
3. When the workflow finishes, download the `.sha256` files from the logs/artifacts and paste the sums into `swaggen/cli.py`.
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
3. Optionally download an archive (for example `swaggen-jre-linux-x86_64.tar.gz`) and verify its checksum locally.
4. Install the published package from PyPI in a clean environment (e.g. `pipx install swaggen`) and run a quick smoke test with `swaggen doctor` and `swaggen list-generators`.
5. Update `plan.md` with release notes or status.

## 6. Troubleshooting
- **Matrix failures**: Re-run the failing job from the Actions UI; Linux ARM64 uses `uraimo/run-on-arch-action` and may flake occasionally.
- **PyPI upload issues**: Ensure `PYPI_API_TOKEN` is valid, assigned to the project, and stored as an Actions secret.
- **Windows packaging quirks**: Download the Temurin JDK manually and execute `scripts/build-jre-windows.ps1` via PowerShell to reproduce locally.
- **Stale caches**: If the embedded JRE changes between releases, warn users to reinstall via `swaggen engine install-jre` or remove the cache directory printed by `swaggen doctor`.

## 7. After the release
- Announce the release (for example in project channels or release notes).
- Close or update any GitHub issues tied to the milestone.
- Archive temporary artifacts (local `tmp-sdks`, downloaded JRE archives) to keep the workspace clean.
