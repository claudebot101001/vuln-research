"""Tests for pipeline/acquire.py — freshness checks and validation gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.acquire import TargetAcquirer
from pipeline.models import FreshnessError, FreshnessReport


# ---------------------------------------------------------------------------
# Freshness check: stale file detection
# ---------------------------------------------------------------------------


class TestFreshnessStaleFiles:
    def test_detects_stale_files(self, tmp_path):
        """Files not committed in >60 days are flagged as stale."""
        # Create a fake sol file
        src = tmp_path / "src"
        src.mkdir()
        (src / "Vault.sol").write_text("pragma solidity ^0.8.0;\ncontract Vault {}")

        # Init a git repo with a commit dated 90 days ago
        _init_git_with_old_commit(tmp_path, src / "Vault.sol", days_ago=90)

        acquirer = TargetAcquirer()
        report = acquirer._check_freshness(tmp_path, [])
        assert len(report.stale_files) == 1
        assert report.stale_files[0]["file"] == "src/Vault.sol"
        assert report.stale_files[0]["days_ago"] >= 89  # allow 1-day tolerance
        assert not report.is_clean

    def test_fresh_file_not_flagged(self, tmp_path):
        """Recently committed files are not flagged."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "Vault.sol").write_text("pragma solidity ^0.8.0;\ncontract Vault {}")

        # Init with a recent commit
        _init_git_with_old_commit(tmp_path, src / "Vault.sol", days_ago=5)

        acquirer = TargetAcquirer()
        report = acquirer._check_freshness(tmp_path, [])
        assert len(report.stale_files) == 0
        assert report.is_clean


# ---------------------------------------------------------------------------
# Freshness check: V2 file detection
# ---------------------------------------------------------------------------


class TestFreshnessV2Detection:
    def test_detects_v2_superseding_file(self, tmp_path):
        """If VaultV2.sol exists alongside Vault.sol, Vault.sol is superseded."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "Vault.sol").write_text("contract Vault {}")
        (src / "VaultV2.sol").write_text("contract VaultV2 {}")

        acquirer = TargetAcquirer()
        report = acquirer._check_freshness(tmp_path, [])
        assert len(report.superseded_files) == 1
        assert report.superseded_files[0]["original"] == "src/Vault.sol"
        assert "VaultV2" in report.superseded_files[0]["replacement"]
        assert not report.is_clean

    def test_no_v2_means_not_superseded(self, tmp_path):
        """Without a V2 file, no superseding detected."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "Vault.sol").write_text("contract Vault {}")

        acquirer = TargetAcquirer()
        report = acquirer._check_freshness(tmp_path, [])
        assert len(report.superseded_files) == 0


# ---------------------------------------------------------------------------
# validate_freshness: raises FreshnessError
# ---------------------------------------------------------------------------


class TestValidateFreshness:
    def test_raises_on_superseded_files(self):
        report = FreshnessReport(
            superseded_files=[{"original": "Vault.sol", "replacement": "VaultV2.sol"}],
            is_clean=False,
        )
        acquirer = TargetAcquirer()
        with pytest.raises(FreshnessError, match="superseded files"):
            acquirer.validate_freshness(report, force=False)

    def test_force_overrides_superseded(self, capsys):
        report = FreshnessReport(
            superseded_files=[{"original": "Vault.sol", "replacement": "VaultV2.sol"}],
            is_clean=False,
        )
        acquirer = TargetAcquirer()
        acquirer.validate_freshness(report, force=True)  # Should NOT raise
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_clean_report_passes(self):
        report = FreshnessReport(is_clean=True)
        acquirer = TargetAcquirer()
        acquirer.validate_freshness(report, force=False)  # Should not raise

    def test_stale_files_warn_without_force(self, capsys):
        report = FreshnessReport(
            stale_files=[
                {"file": "Vault.sol", "last_modified": "90d ago", "days_ago": 90}
            ],
            is_clean=False,
        )
        acquirer = TargetAcquirer()
        # Stale files without superseded files just warn, don't raise
        acquirer.validate_freshness(report, force=False)
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "STALE" in captured.out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _init_git_with_old_commit(repo_dir: Path, file_path: Path, days_ago: int):
    """Initialize a git repo with a single commit dated `days_ago` days in the past."""
    import subprocess
    import time

    # Calculate past timestamp
    past_ts = int(time.time()) - (days_ago * 86400)
    date_str = f"@{past_ts} +0000"

    env = {
        "GIT_AUTHOR_DATE": date_str,
        "GIT_COMMITTER_DATE": date_str,
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@test.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@test.com",
        "HOME": str(repo_dir),
        "PATH": "/usr/bin:/bin:/usr/local/bin",
    }

    subprocess.run(["git", "init"], cwd=str(repo_dir), capture_output=True, env=env)
    subprocess.run(
        ["git", "add", str(file_path.relative_to(repo_dir))],
        cwd=str(repo_dir),
        capture_output=True,
        env=env,
    )
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=str(repo_dir),
        capture_output=True,
        env=env,
    )
