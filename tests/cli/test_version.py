from typer.testing import CliRunner

from cyllex_argus import __version__
from cyllex_argus.cli.app import app


def test_version_flag_prints_version():
    """Pinned to the package __version__ instead of a literal so a semver bump stays green."""
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"Cyllex Argus {__version__}" in result.output
