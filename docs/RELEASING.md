# Releasing swaggen

This guide walks through shipping a tagged release with bundled JRE assets and PyPI artifacts.

## 1. Prepare the repo

1. Ensure `main` is up to date and the changelog/plan is ready.
2. Run the test suite locally: `python -m pytest`.
3. (Optional) Build and sanity check the CLI with the embedded JRE on macOS using `swaggen engine install-jre` and `swaggen gen ...`.

## 2. Tag the release

```bash
# Bump versions as needed (pyproject.toml, swaggen/__init__.py, etc.)
git commit -am "Release v0.x.y"
git tag v0.x.y
git push origin main --tags
```

Pushing the `v*` tag triggers the `release` workflow automatically.

## 3. What the GitHub Actions workflows do

### `release.yml`

1. **build-jres** (matrix)
   - Downloads Temurin JDKs for linux (x64 + arm64), macOS (Intel + Apple Silicon), and Windows.
   - Invokes `scripts/build-jre-*.{sh,ps1}` to produce trimmed runtimes.
   - Uploads each archive and `.sha256` checksum to the GitHub release created for the tag.
2. **publish** (needs: build-jres)
   - Builds the source and wheel distributions via `python -m build`.
   - Publishes to PyPI using `PYPI_API_TOKEN`.
3. **binaries** (optional)
   - Runs PyInstaller across Linux/macOS/Windows and uploads single-file executables to the release.

### `ci.yml`

- Runs `python -m pytest` against Python 3.8 and 3.11 on Ubuntu, macOS (Intel + ARM), and Windows for every push/PR.

## 4. Verify the release

1. Wait for the `release` workflow to finish and confirm the JRE assets appear under the release.
2. Download one of the artifacts (e.g., `swaggen-jre-linux-x86_64.tar.gz`) and verify the checksum locally if desired.
3. Install the published package from PyPI in a clean environment (e.g., via `pipx install swaggen`) and run a smoke test.
4. Update `plan.md` with the release details and mark checklist items completed.

## 5. Troubleshooting

- If the JRE build job fails on Linux ARM64, re-run that matrix item from the Actions UI (the job uses `uraimo/run-on-arch-action`).
- If PyPI upload fails, ensure `PYPI_API_TOKEN` is set in the repo secrets and has the correct privileges.
- For Windows-specific JRE issues, download the JDK URL manually and run `scripts/build-jre-windows.ps1` with PowerShell to reproduce.

