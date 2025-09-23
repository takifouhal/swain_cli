Below is a single, implementation‑ready document, it makes concrete choices where alternatives existed and includes complete code, packaging, CI, and usage details.

---

# Project: **swain_cli** — Zero‑setup SDK generator from OpenAPI

**Goal**: Deliver a CLI that takes a Swagger/OpenAPI schema and generates SDK clients for chosen target languages using **OpenAPI Generator**, with **no user setup** beyond installing our CLI.

**Primary UX**: `pipx install swain_cli` → `swain_cli gen -i openapi.yaml -l python -l typescript -o sdks`


## Progress updates
- 2025-09-20: Created project scaffolding, implemented CLI, added vendor jar, release workflow, build scripts, and example configs. Updated README with third-party notices and recorded checklist progress.
- 2025-09-20: Built macOS arm64 trimmed JRE, captured SHA-256, expanded build scripts to include java.se/jdk.unsupported modules, validated `list-generators` and `gen` via system engine using local JRE, and updated `.gitignore` for generated artifacts.
- 2025-09-20: Added `build-jre` CI workflow with multi-platform matrix, updated scripts to emit `.sha256` files, simplified release pipeline, and documented maintainer runbook for producing JRE assets.
- 2025-09-20: Built macOS x86_64 trimmed JRE, regenerated macOS arm64 JRE to capture new checksum, and updated `swain_cli/cli.py` with both SHA-256 values.
- 2025-09-21: Added Apache-2.0 LICENSE, documented dev workflow, wired release build-jres job (Linux/Windows/macOS), taught CLI to consume release checksum files with basic tests, introduced cross-platform CI, and validated the matrix in run [#17884613705](https://github.com/takifouhal/swain_cli/actions/runs/17884613705).
- 2025-09-22: Adopted Typer/httpx/questionary/platformdirs/keyring/pooch across the CLI, refreshed docs/tests, and confirmed `swain_cli doctor` works post-migration.


---

## 1) Design decisions (locked)

These choices are made to optimize developer experience, reproducibility, and maintenance.

1. **Engine packaging**:
   **Vendored OpenAPI Generator JAR + lazy‑downloaded embedded JRE** (a trimmed `jlink` JRE per OS, downloaded automatically on first run and cached).
   *Why*: Users get zero setup; PyPI package stays small; we avoid shipping huge, OS‑specific wheels.

2. **Language & runtime for our CLI**:
   **Python 3.8+** with a slim dependency stack (Typer, httpx, questionary, platformdirs, keyring, pooch). Distribute via **pipx** (primary) and **PyInstaller one‑file binaries** (optional).

3. **Pinned versions**:

   * OpenAPI Generator CLI: **`7.6.0`**
   * Embedded JRE: OpenJDK 21 (**Temurin 21.0.4**) trimmed with `jlink`
     *Why*: Reproducible, predictable output. Users can opt into newer engine via an explicit command.

4. **Default engine mode**: **embedded** (our JRE).
   Optional `--engine system` lets power users use a locally installed Java.

5. **Output layout**:
   `--out <base>` produces one subfolder per generator:
   `sdks/python`, `sdks/typescript-axios`, `sdks/go`, etc.

6. **TypeScript alias**: `typescript` → `typescript-axios`.
   *Why*: Most teams expect Axios by default; power users can request `typescript-fetch`.

7. **Security**: Cache artifacts in a user cache dir and (optionally) verify SHA‑256 for JRE archives.

8. **Features in v1**: `gen`, `list-generators`, `doctor`, `engine` manager (status/install/update).
   (No GUI, no project scaffolding wizard — keep core tight.)

---

## 2) CLI behavior & UX spec

### Commands

* `swain_cli doctor`
  Prints environment and engine status. Does not mutate state.

* `swain_cli list-generators [--engine embedded|system]`
  Runs `openapi-generator list` using our bundled engine.

* `swain_cli gen -i|--schema <path|url> -l|--lang <gen> [-l <gen> ...] -o|--out <dir> [options]`
  Generates SDKs for one or more generators. Accepts paths or URLs for schemas.

* `swain_cli engine <action>`
  Engine utilities:

  * `status` – shows system Java, embedded JRE/JAR status
  * `install-jre` – prefetch and install the embedded JRE for the current platform
  * `update-jar --version <x.y.z>` – cache a different OpenAPI Generator JAR (does not republish our wheel)
  * `use-system|use-embedded` – prints how to select engine via CLI flag

### Common options (for `gen`)

* `-c, --config <file>` – openapi‑generator native config (YAML/JSON)
* `-t, --templates <dir>` – custom mustache templates
* `-p, --additional-properties key=value` (repeatable)
* `--generator-arg <arg>` (repeatable) – raw pass‑through to openapi‑generator
* `--skip-validate-spec` – pass through
* `-v, --verbose` – pass `-v` to openapi‑generator
* `--engine [embedded|system]` – choose Java source (default `embedded`)

### Exit codes

* `0` success
* `1` sub‑process (openapi‑generator) returned non‑zero
* `2` CLI usage or pre‑flight errors (missing files, unsupported platform, etc.)

### Logging

* All swain_cli messages are prefixed with `[swain_cli]`.
* We stream the generator’s stdout/stderr live (no buffering), so users see progress.

---

## 3) Repository layout

```
swain_cli/
├── pyproject.toml
├── MANIFEST.in
├── README.md
├── swain_cli/
│   ├── __init__.py
│   ├── cli.py                # <-- main CLI (complete code below)
│   └── vendor/
│       └── openapi-generator-cli-7.6.0.jar
├── scripts/
│   ├── build-jre-linux.sh    # produce trimmed JRE tarballs + sha256
│   ├── build-jre-macos.sh
│   └── build-jre-windows.ps1
└── .github/workflows/
    └── release.yml           # build & publish wheel + optional binaries + attach JRE assets
```

---

## 4) Complete CLI (drop-in)

Save as `swain_cli/cli.py`.

> Fill in `ASSET_BASE` and `JRE_ASSETS` filenames; you’ll publish these JRE archives via GitHub Releases (see §6). You can initially set the SHA fields to `None` during bring‑up; add real SHA‑256s before release.

```python
#!/usr/bin/env python3
# swain_cli/cli.py
import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from urllib.request import urlopen

# ====== Versions and assets ======
ENGINE_VERSION = "7.6.0"  # OpenAPI Generator CLI version we ship
ENGINE_JAR_NAME = f"openapi-generator-cli-{ENGINE_VERSION}.jar"
MAVEN_URL = f"https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/{ENGINE_VERSION}/{ENGINE_JAR_NAME}"

# Host per-OS trimmed JRE archives you build with jlink (see scripts/ and CI section).
# Example: https://github.com/takifouhal/swain_cli/releases/download/jre-21.0.4/<files>
ASSET_BASE = "https://github.com/takifouhal/swain_cli/releases/download/jre-21.0.4"

# Map of (OS, ARCH) to (filename, sha256 or None). Fill with real SHA256 before release.
JRE_ASSETS: Dict[tuple, tuple] = {
    ("Linux", "x86_64"): ("jre-21.0.4-temurin-linux-x64.tar.gz",     None),
    ("Linux", "aarch64"): ("jre-21.0.4-temurin-linux-aarch64.tar.gz", None),
    ("Darwin", "x86_64"): ("jre-21.0.4-temurin-macos-x64.tar.gz",     None),
    ("Darwin", "arm64"):  ("jre-21.0.4-temurin-macos-aarch64.tar.gz", None),
    ("Windows", "AMD64"): ("jre-21.0.4-temurin-windows-x64.zip",      None),
}

# ====== Cache directory ======
def default_cache_dir() -> Path:
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "swain_cli"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "swain_cli"
    else:
        return Path.home() / ".cache" / "swain_cli"

CACHE_DIR = default_cache_dir()

# ====== Utilities ======
def info(msg: str): print(f"[swain_cli] {msg}")
def die(msg: str, code: int = 2): print(f"error: {msg}", file=sys.stderr); sys.exit(code)
def which(cmd: str) -> Optional[str]: return shutil.which(cmd)

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def download(url: str, dest: Path, expected_sha256: Optional[str] = None):
    dest.parent.mkdir(parents=True, exist_ok=True)
    info(f"Downloading {url}")
    with urlopen(url) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)
    if expected_sha256:
        actual = sha256_file(dest)
        if actual.lower() != expected_sha256.lower():
            dest.unlink(missing_ok=True)
            die(f"SHA256 mismatch for {dest.name}. expected={expected_sha256} actual={actual}")

def extract_archive(archive: Path, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    if archive.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive) as z:
            z.extractall(dest_dir)
            names = z.namelist()
            root = names[0].split("/")[0]
            return dest_dir / root
    else:
        with tarfile.open(archive) as t:
            t.extractall(dest_dir)
            first = t.getmembers()[0].name.split("/")[0]
            return dest_dir / first

# ====== Engine manager ======
@dataclass
class EnginePaths:
    java_bin: Path
    jar_path: Path

class EngineManager:
    def __init__(self, cache_dir: Path = CACHE_DIR):
        self.cache = cache_dir
        self.jre_dir = self.cache / "jre"
        self.jar_dir = self.cache / "openapi-generator"
        self.pkg_dir = Path(__file__).parent  # swain_cli package dir

    def _platform_key(self) -> tuple:
        return (platform.system(), platform.machine())

    def _embedded_jar(self) -> Optional[Path]:
        # Look for vendored jar inside the package
        candidate = self.pkg_dir / "vendor" / ENGINE_JAR_NAME
        return candidate if candidate.exists() else None

    def ensure_jar(self, prefer_embedded=True) -> Path:
        if prefer_embedded:
            emb = self._embedded_jar()
            if emb:
                return emb
        # Download to cache if not vendored
        self.jar_dir.mkdir(parents=True, exist_ok=True)
        jar = self.jar_dir / ENGINE_JAR_NAME
        if not jar.exists():
            download(MAVEN_URL, jar)  # optionally pin sha256 if desired
        return jar

    def system_java(self) -> Optional[Path]:
        j = which("java")
        return Path(j) if j else None

    def ensure_embedded_jre(self) -> Path:
        os_name, arch = self._platform_key()
        key = (os_name, arch)
        if key not in JRE_ASSETS:
            die(f"Unsupported platform: {key}. Try --engine system.")
        filename, sha256sum = JRE_ASSETS[key]
        dest = self.jre_dir / filename
        root_dir = self.jre_dir / filename.replace(".tar.gz", "").replace(".zip", "")

        java_rel = "bin/java.exe" if os_name == "Windows" else "bin/java"
        if (root_dir / java_rel).exists():
            return root_dir

        self.jre_dir.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            url = f"{ASSET_BASE}/{filename}"
            download(url, dest, expected_sha256=sha256sum)
        extracted_root = extract_archive(dest, self.jre_dir)
        return extracted_root

    def engine_paths(self, engine: str) -> EnginePaths:
        """
        engine: 'embedded' | 'system'
        """
        jar = self.ensure_jar(prefer_embedded=True)
        if engine == "system":
            java_bin = self.system_java()
            if not java_bin:
                die("No system Java found. Either install Java or use --engine embedded.")
            return EnginePaths(java_bin=java_bin, jar_path=jar)
        else:
            jre_root = self.ensure_embedded_jre()
            java_rel = "bin/java.exe" if platform.system() == "Windows" else "bin/java"
            java_bin = jre_root / java_rel
            if not java_bin.exists():
                die(f"Embedded Java not found at {java_bin}")
            if platform.system() != "Windows":
                java_bin.chmod(java_bin.stat().st_mode | 0o111)
            return EnginePaths(java_bin=java_bin, jar_path=jar)

# ====== Generator wrappers ======
def run_and_stream(cmd: List[str], cwd: Optional[Path] = None) -> int:
    proc = subprocess.Popen(cmd, cwd=str(cwd) if cwd else None)
    return proc.wait()

def list_generators(paths: EnginePaths) -> int:
    return run_and_stream([str(paths.java_bin), "-jar", str(paths.jar_path), "list"])

def og_generate(paths: EnginePaths, gen: str, schema: str, out: Path,
                config: Optional[Path], templates: Optional[Path],
                add_props: Dict[str, str], skip_validate: bool, verbose: bool,
                passthrough: List[str]) -> int:
    cmd = [str(paths.java_bin), "-jar", str(paths.jar_path),
           "generate", "-g", gen, "-i", schema, "-o", str(out)]
    if add_props:
        ap = ",".join(f"{k}={v}" for k, v in add_props.items())
        cmd += ["--additional-properties", ap]
    if config:    cmd += ["-c", str(config)]
    if templates: cmd += ["-t", str(templates)]
    if skip_validate: cmd += ["--skip-validate-spec"]
    if verbose: cmd += ["-v"]
    if passthrough: cmd += passthrough
    info(f"Generating {gen} → {out}")
    return run_and_stream(cmd)

# ====== CLI ======
ALIASES = {
    "python": "python",
    "typescript": "typescript-axios",
    "ts": "typescript-axios",
    "typescript-axios": "typescript-axios",
    "typescript-fetch": "typescript-fetch",
    "go": "go",
    "swift": "swift5",
    "swift5": "swift5",
    "java": "java",
    "kotlin": "kotlin",
    "csharp": "csharp",
    "ruby": "ruby",
    "php": "php",
    "rust": "rust",
    "dart": "dart",
    "scala": "scala",
}

def res_gen(name: str) -> str: return ALIASES.get(name.lower(), name)

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="swain_cli: generate SDKs from OpenAPI with a fully bundled engine.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("doctor", help="Check engine status.")
    sp.add_argument("--engine", choices=["embedded", "system"], default="embedded")
    sp.set_defaults(func=cmd_doctor)

    sp = sub.add_parser("list-generators", help="List generators available in the bundled engine.")
    sp.add_argument("--engine", choices=["embedded", "system"], default="embedded")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("gen", help="Generate SDK(s).")
    sp.add_argument("-i", "--schema", required=True, help="Path or URL to OpenAPI/Swagger (json/yaml).")
    sp.add_argument("-l", "--lang", action="append", required=True, help="Target language(s). Repeat or comma-separate.")
    sp.add_argument("-o", "--out", required=True, help="Output base dir; each generator writes to a subdir.")
    sp.add_argument("--engine", choices=["embedded", "system"], default="embedded", help="Which Java to use.")
    sp.add_argument("-c", "--config", default=None, help="openapi-generator config file (YAML/JSON).")
    sp.add_argument("-t", "--templates", default=None, help="Custom templates dir.")
    sp.add_argument("-p", "--additional-properties", action="append", help="key=value, repeatable.")
    sp.add_argument("--skip-validate-spec", action="store_true")
    sp.add_argument("--verbose", "-v", action="store_true")
    sp.add_argument("--generator-arg", action="append", help="Pass-through args to openapi-generator.")
    sp.set_defaults(func=cmd_gen)

    sp = sub.add_parser("engine", help="Manage the bundled engine (JRE/JAR).")
    sp.add_argument("action", choices=["status", "install-jre", "update-jar", "use-system", "use-embedded"])
    sp.add_argument("--version", help="OpenAPI Generator version for update-jar.")
    sp.set_defaults(func=cmd_engine)
    return p

def parse_kv(items: Optional[List[str]]) -> Dict[str, str]:
    out = {}
    if not items: return out
    for kv in items:
        if "=" not in kv: die(f"--additional-properties expects key=value, got: {kv}")
        k, v = kv.split("=", 1)
        out[k] = v
    return out

# ---- subcommands
def cmd_doctor(args: argparse.Namespace) -> int:
    em = EngineManager()
    info(f"Cache dir: {CACHE_DIR}")
    info(f"OpenAPI Generator (pinned): {ENGINE_VERSION}")
    if args.engine == "system":
        j = em.system_java()
        print(f"  system java: {j if j else 'not found'}")
        print(f"  bundled jar: {em._embedded_jar() or '(will download to cache)'}")
        return 0
    else:
        try:
            jre = em.ensure_embedded_jre()
            print(f"  embedded JRE: {jre}")
        except SystemExit:
            print("  embedded JRE: not installed")
        emb = em._embedded_jar()
        print(f"  embedded JAR: {emb if emb else '(will use cached/downloaded jar)'}")
        return 0

def cmd_list(args: argparse.Namespace) -> int:
    em = EngineManager()
    paths = em.engine_paths(args.engine)
    return list_generators(paths)

def cmd_gen(args: argparse.Namespace) -> int:
    em = EngineManager()
    paths = em.engine_paths(args.engine)
    out_base = Path(args.out).expanduser().resolve()
    out_base.mkdir(parents=True, exist_ok=True)

    langs: List[str] = []
    for l in (args.lang or []):
        langs += [x.strip() for x in l.split(",") if x.strip()]
    langs = [res_gen(x) for x in langs]
    langs = list(dict.fromkeys(langs))  # de-dup

    add_props = parse_kv(args.additional_properties)
    passtr = args.generator_arg or []
    rc = 0
    for gen in langs:
        rc = og_generate(paths, gen, args.schema, out_base / gen,
                         Path(args.config) if args.config else None,
                         Path(args.templates) if args.templates else None,
                         add_props, args.skip_validate_spec, args.verbose, passtr)
        if rc != 0: return rc
    return rc

def cmd_engine(args: argparse.Namespace) -> int:
    em = EngineManager()
    if args.action == "status":
        j = em.system_java()
        print(f"system java: {j if j else 'not found'}")
        try:
            jre = em.ensure_embedded_jre()
            print(f"embedded JRE: {jre}")
        except SystemExit:
            print("embedded JRE: not installed")
        emb = em._embedded_jar()
        print(f"embedded JAR: {emb if emb else 'not bundled (using cache/download)'}")
        cached = em.jar_dir / ENGINE_JAR_NAME
        print(f"cached JAR: {cached if cached.exists() else 'not downloaded'}")
        return 0

    if args.action == "install-jre":
        em.ensure_embedded_jre()
        info("Embedded JRE installed.")
        return 0

    if args.action == "update-jar":
        ver = args.version or ENGINE_VERSION
        jar = em.jar_dir / f"openapi-generator-cli-{ver}.jar"
        if not jar.exists():
            url = f"https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/{ver}/openapi-generator-cli-{ver}.jar"
            download(url, jar)
        info(f"Cached {jar}")
        return 0

    if args.action in ("use-system", "use-embedded"):
        mode = "system" if args.action == "use-system" else "embedded"
        info(f"Use this with: swain_cli gen ... --engine {mode}")
        return 0

    return 0

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
```

---

## 5) Packaging (PyPI) — **pipx first‑run experience**

### `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "swain_cli"
version = "0.2.0"
description = "Zero-setup SDK generator from OpenAPI (bundled engine)"
readme = "README.md"
requires-python = ">=3.8"
authors = [{ name = "Your Team" }]
dependencies = []

[project.scripts]
swain_cli = "swain_cli.cli:main"

[tool.setuptools.package-data]
"swain_cli" = ["vendor/openapi-generator-cli-*.jar"]

[tool.setuptools]
zip-safe = false
```

### `MANIFEST.in`

```
include swain_cli/vendor/openapi-generator-cli-*.jar
```

> Place `openapi-generator-cli-7.6.0.jar` under `swain_cli/vendor/` so the wheel works **offline** for the JAR.
> The JRE is downloaded on first run, cached in `~/.cache/swain_cli` (Linux), `~/Library/Caches/swain_cli` (macOS), or `%LOCALAPPDATA%\swain_cli` (Windows).

---

## 6) Building & hosting the trimmed JREs

We ship one JRE per OS/arch, produced using `jlink` from Temurin JDK 21.0.4.
Minimal module set that works well with OpenAPI Generator:

```
java.base,java.logging,java.xml,java.desktop,jdk.zipfs
```

> Add modules if you hit a missing class at runtime.

### Example (Linux/macOS) — `scripts/build-jre-linux.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

JDK_HOME="${JDK_HOME:-$HOME/.jdk-temurin-21}"   # set to your Temurin JDK 21
OUT="dist"
VER="21.0.4-temurin"
NAME="jre-${VER}-linux-x64"  # adjust per arch
MODULES="java.base,java.logging,java.xml,java.desktop,jdk.zipfs"

rm -rf "$OUT/$NAME"
"$JDK_HOME/bin/jlink" \
  --no-header-files --no-man-pages \
  --strip-debug --compress=2 \
  --add-modules "$MODULES" \
  --output "$OUT/$NAME"

tar -C "$OUT" -czf "$OUT/${NAME}.tar.gz" "$NAME"
sha256sum "$OUT/${NAME}.tar.gz" > "$OUT/${NAME}.tar.gz.sha256"
```

> Provide similar scripts for macOS ARM (`NAME=...-macos-aarch64`) and Windows (PowerShell with `Compress-Archive` to `.zip`).
> Build each artifact on its native OS in CI (see next section). Attach them to a **GitHub Release** named e.g. `jre-21.0.4`.

### Publish & wire into the CLI

* Upload the archives to the Release tagged `jre-21.0.4`.
* Set `ASSET_BASE = "https://github.com/takifouhal/swain_cli/releases/download/jre-21.0.4"`.
* Copy each `.sha256` value into `JRE_ASSETS[(OS, ARCH)]`.

---

## 7) CI/CD (GitHub Actions)

Create `.github/workflows/release.yml`.

```yaml
name: Release
on:
  push:
    tags: ["v*.*.*"]

jobs:
  build-jres:
    # Build trimmed JREs on native runners, attach to a JRE release
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            script: scripts/build-jre-linux.sh
            artifact: "dist/jre-21.0.4-temurin-linux-x64.tar.gz"
          - os: macos-13
            script: scripts/build-jre-macos.sh
            artifact: "dist/jre-21.0.4-temurin-macos-x64.tar.gz"
          - os: macos-14
            script: scripts/build-jre-macos-arm.sh
            artifact: "dist/jre-21.0.4-temurin-macos-aarch64.tar.gz"
          - os: windows-latest
            script: scripts/build-jre-windows.ps1
            artifact: "dist/jre-21.0.4-temurin-windows-x64.zip"
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - name: Build JRE
        shell: ${{ endsWith(matrix.os, 'windows-latest') && 'pwsh' || 'bash' }}
        run: ${{ matrix.script }}
      - name: Upload JREs to a dedicated JRE release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: jre-21.0.4
          files: ${{ matrix.artifact }}

  publish-pypi:
    runs-on: ubuntu-latest
    needs: [build-jres]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - name: Build wheel
        run: |
          python -m pip install build
          python -m build
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@v1.9.0
        with:
          password: ${{ secrets.PYPI_API_TOKEN }}

  binaries: # optional single-file executables
    strategy:
      matrix:
        os: [ubuntu-latest, macos-13, macos-14, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - name: Build onefile
        run: |
          python -m pip install pyinstaller
          pyinstaller -n swain_cli --onefile swain_cli/cli.py \
            --add-data "swain_cli/vendor/openapi-generator-cli-7.6.0.jar:swain_cli/vendor"
      - name: Upload binaries to release
        uses: softprops/action-gh-release@v2
        with:
          files: dist/*/swain_cli*
```

> **Note**: The JRE release job runs once per `v*.*.*` tag in this example; adapt to your versioning flow.
> Before first real release, you can pre‑create `jre-21.0.4` manually and upload assets with the `build-jres` job.

---

## 8) Quickstart for users (docs/README excerpt)

```bash
# Install (recommended)
pipx install swain_cli

# (optional) Pre-install the bundled JRE to avoid first-run download
swain_cli engine install-jre

# Show supported generators (from the bundled engine)
swain_cli list-generators

# Generate Python + TypeScript SDKs into ./sdks/*
swain_cli gen -i ./openapi.yaml -l python -l typescript -o ./sdks \
  -p packageName=my_api_client -p packageVersion=0.2.0

# Use custom generator config and templates
swain_cli gen -i ./openapi.yaml -l python -o ./sdks \
  -c ./configs/python.yaml -t ./templates/python
```

---

## 9) Example generator configs (repo examples)

`examples/python-config.yaml`

```yaml
packageName: my_api_client
projectName: my_api_client
packageVersion: 0.2.0
generateSourceCodeOnly: true
enumPropertyNaming: PascalCase
```

`examples/ts-axios-config.yaml`

```yaml
npmName: "@acme/api-client"
npmVersion: 0.2.0
supportsES6: true
withInterfaces: true
useSingleRequestParameter: true
```

---

## 10) Implementation checklist

* [x] Add `openapi-generator-cli-7.6.0.jar` to `swain_cli/vendor/`.
* [ ] Trigger the `build-jres` CI job to publish trimmed JRE assets for `jre-21.0.4` (automation committed; run on release tag to upload linux/windows bundles).
* [x] Ensure CLI verifies JRE downloads via release `.sha256` files (no more placeholder hashes).
* [x] Commit `pyproject.toml`, `MANIFEST.in`, `README.md`.
* [ ] Tag `v0.2.0` and push; verify CI publishes the wheel and (optionally) binaries (tag pushed; monitor release workflow for completion).
* [x] Test on Linux x64, macOS (Intel + ARM), Windows x64 (covered by `ci.yml`; first green run: [#17884613705](https://github.com/takifouhal/swain_cli/actions/runs/17884613705)).

  * macOS arm64: [x] `swain_cli doctor`, [x] `swain_cli list-generators` (system engine via local trimmed JRE), [x] `swain_cli gen -i https://petstore3.swagger.io/api/v3/openapi.json -l python -l typescript -o sdks --engine system` (outputs removed after verification)
  * macOS x86_64: [x] Covered by CI run #17884613705
  * Linux x86_64: [x] Covered by CI run #17884613705
  * Windows x86_64: [x] Covered by CI run #17884613705
* [x] Add minimal “Third‑party notices” section in README (OpenAPI Generator Apache‑2.0; OpenJDK GPLv2+CE).

---

## 11) Error handling & edge cases (what to implement)

* Missing schema file ⇒ exit 2 with message: `error: Schema not found: <path>`.
* Unsupported platform (no JRE asset) ⇒ suggest `--engine system`.
* First‑run download failures ⇒ clear message with the URL and cache path.
* URL schemas are passed through (no local mount logic needed).
* Windows path quirks handled via `subprocess` arg lists (already done).
* If a generator returns non‑zero, abort the batch and propagate its exit code.

---

## 12) Sensible defaults we picked (can be revisited later)

* Default engine: **embedded**.
* `typescript` alias → **`typescript-axios`**.
* Cache location: OS‑standard user cache dir.
* Streaming subprocess output; no log files by default.

---

## 13) Future (non‑blocking) improvements

* `--offline` flag to forbid network and require cached/vendored artifacts.
* “Presets” (org‑opinionated bundles of config + props) via `--preset <name>`.
* `swain_cli validate` wrapper for `openapi-generator validate`.
* Telemetry (opt‑in) to count generator usage for prioritization.

---

### Done.

This document is self‑contained: the developer can drop in the code, build the JRE assets, and ship a zero‑setup CLI that bundles OpenAPI Generator and generates SDKs reliably across platforms.
