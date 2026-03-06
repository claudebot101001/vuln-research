"""Target acquisition + freshness checks (hard gate)."""

from __future__ import annotations

import re
import subprocess
from collections import Counter
from pathlib import Path

from .models import AcquiredTarget, FreshnessError, FreshnessReport, ScanConfig


class TargetAcquirer:
    """Clone or locate target, detect solc, check freshness."""

    def acquire(self, config: ScanConfig) -> AcquiredTarget:
        target_dir = self._clone_or_locate(config.target)
        solc_version = config.solc_version or self._detect_solc_version(target_dir)
        if solc_version:
            self._ensure_solc(solc_version)
        freshness = self._check_freshness(target_dir, config.scope_contracts)
        return AcquiredTarget(
            path=target_dir,
            solc_version=solc_version,
            freshness=freshness,
        )

    def validate_freshness(
        self, freshness: FreshnessReport, force: bool = False
    ) -> None:
        """Abort pipeline if freshness check fails. Unless force=True."""
        if freshness.superseded_files:
            msg = "ABORT: Found superseded files:\n"
            for sf in freshness.superseded_files:
                msg += f"  {sf['original']} -> replaced by {sf['replacement']}\n"
            if not force:
                raise FreshnessError(msg + "Use --force to override.")
            else:
                print(f"WARNING (--force): {msg}")

        if not freshness.is_clean and not force:
            print("WARNING: Freshness issues detected. Use --force to override.")
            for sf in freshness.stale_files:
                print(f"  STALE: {sf['file']} (last modified {sf['days_ago']}d ago)")

    # -- internal --

    def _clone_or_locate(self, target: str) -> Path:
        """Clone repo or return local path."""
        if target.startswith(("http://", "https://", "git@")):
            repo_name = target.rstrip("/").split("/")[-1].replace(".git", "")
            dest = Path("targets") / repo_name
            if not dest.exists():
                subprocess.run(
                    ["git", "clone", "--depth", "1", target, str(dest)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            return dest
        return Path(target)

    def _detect_solc_version(self, target_dir: Path) -> str | None:
        """Detect Solidity version from pragma statements."""
        versions: list[str] = []
        for sol_file in target_dir.rglob("*.sol"):
            try:
                content = sol_file.read_text(errors="ignore")
                matches = re.findall(
                    r"pragma\s+solidity\s+[\^~>=<]*(\d+\.\d+\.\d+)", content
                )
                versions.extend(matches)
            except Exception:
                continue
        if not versions:
            return None
        return Counter(versions).most_common(1)[0][0]

    def _ensure_solc(self, version: str) -> None:
        """Install solc version if not available."""
        result = subprocess.run(
            ["solc-select", "versions"], capture_output=True, text=True
        )
        if version not in result.stdout:
            subprocess.run(["solc-select", "install", version], capture_output=True)
        subprocess.run(["solc-select", "use", version], capture_output=True)

    def _check_freshness(
        self, target_dir: Path, scope_contracts: list[str]
    ) -> FreshnessReport:
        """Check freshness of in-scope contracts.

        For each in-scope contract:
        1. git log --since=60d -- <file>  (recent changes?)
        2. Search for V2/V3/renamed versions in same directory
        3. Check deploy scripts for references
        """
        stale_files: list[dict] = []
        superseded_files: list[dict] = []
        scope_drift: list[dict] = []

        # Determine files to check
        if scope_contracts:
            sol_files = []
            for pattern in scope_contracts:
                sol_files.extend(target_dir.rglob(pattern))
        else:
            sol_files = [
                f
                for f in target_dir.rglob("*.sol")
                if not any(
                    p in f.parts
                    for p in ("test", "script", "lib", "node_modules", "forge-std")
                )
            ]

        is_git = (target_dir / ".git").exists()

        for sol_file in sol_files:
            rel_path = str(sol_file.relative_to(target_dir))

            # 1. Check staleness via git log
            if is_git:
                days_ago = self._days_since_last_commit(target_dir, rel_path)
                if days_ago is not None and days_ago > 60:
                    stale_files.append(
                        {
                            "file": rel_path,
                            "last_modified": f"{days_ago}d ago",
                            "days_ago": days_ago,
                        }
                    )

            # 2. Check for V2/V3 superseding files
            replacement = self._find_superseding_file(sol_file)
            if replacement:
                superseded_files.append(
                    {
                        "original": rel_path,
                        "replacement": str(replacement.relative_to(target_dir)),
                    }
                )

        is_clean = not stale_files and not superseded_files and not scope_drift
        return FreshnessReport(
            stale_files=stale_files,
            superseded_files=superseded_files,
            scope_drift=scope_drift,
            is_clean=is_clean,
        )

    def _days_since_last_commit(self, repo_dir: Path, file_path: str) -> int | None:
        """Get days since last commit touching this file."""
        try:
            result = subprocess.run(
                [
                    "git",
                    "log",
                    "-1",
                    "--format=%ct",
                    "--",
                    file_path,
                ],
                capture_output=True,
                text=True,
                cwd=str(repo_dir),
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None
            import time

            commit_ts = int(result.stdout.strip())
            now_ts = int(time.time())
            return (now_ts - commit_ts) // 86400
        except Exception:
            return None

    def _find_superseding_file(self, sol_file: Path) -> Path | None:
        """Check if a V2/V3 version of this file exists in the same directory."""
        stem = sol_file.stem  # e.g. "Vault"
        parent = sol_file.parent

        # Check for VaultV2.sol, VaultV3.sol, etc.
        for suffix_num in range(2, 5):
            candidate = parent / f"{stem}V{suffix_num}.sol"
            if candidate.exists() and candidate != sol_file:
                return candidate

        return None
