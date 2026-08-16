"""Tests for CLI: db init and run subcommands."""
import asyncio
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from watchtower.cli import _scanner_loop, main
from watchtower.events import Scanner


def test_cli_db_init_creates_schema(tmp_path: Path):
    db = tmp_path / "wt.db"
    runner = CliRunner()
    result = runner.invoke(main, ["db", "init", "--db", str(db)])
    assert result.exit_code == 0, result.output
    assert db.exists()
    with sqlite3.connect(db) as conn:
        v = conn.execute("SELECT version FROM schema_meta").fetchone()
        assert v[0] == 7


@pytest.mark.asyncio
async def test_scanner_loop_restarts_after_failure():
    stop = asyncio.Event()

    class FlakyScanner:
        name = Scanner.WIFI
        attempts = 0

        async def start(self):
            self.attempts += 1
            if self.attempts == 1:
                raise RuntimeError("temporary failure")
            stop.set()

    scanner = FlakyScanner()
    await _scanner_loop(scanner, stop, retry_sec=0.001)
    assert scanner.attempts == 2


def test_cli_help_lists_run_subcommand():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert "run" in result.output
    assert "db" in result.output
