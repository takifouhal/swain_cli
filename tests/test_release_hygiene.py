import re
from pathlib import Path

import swain_cli


def test_homebrew_formula_version_matches_package_version():
    formula = Path("Formula/swain_cli.rb").read_text(encoding="utf-8")
    match = re.search(r'(?m)^\s*version\s+"([^"]+)"\s*$', formula)
    assert match, "failed to locate version in Formula/swain_cli.rb"
    assert match.group(1) == swain_cli.__version__
