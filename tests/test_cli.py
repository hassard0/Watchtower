"""Tests for CLI: db init and run subcommands."""
import sqlite3
from pathlib import Path

from click.testing import CliRunner

from watchtower.cli import main


def test_cli_db_init_creates_schema(tmp_path: Path):
    db = tmp_path / "wt.db"
    runner = CliRunner()
    result = runner.invoke(main, ["db", "init", "--db", str(db)])
    assert result.exit_code == 0, result.output
    assert db.exists()
    with sqlite3.connect(db) as conn:
        v = conn.execute("SELECT version FROM schema_meta").fetchone()
    assert v[0] == 4


def test_cli_help_lists_run_subcommand():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert "run" in result.output
    assert "db" in result.output
