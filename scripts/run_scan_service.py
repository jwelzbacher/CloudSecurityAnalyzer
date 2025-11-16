#!/usr/bin/env python3
"""
Helper script to run CS Kit scans programmatically.

Executes a scan using cs_kit CLI internals and outputs metadata in JSON format.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from cs_kit.cli.config import RunConfig
from cs_kit.cli.main import _run_scan, console as cli_console  # type: ignore[attr-defined]


def generate_run_id() -> str:
    """Generate a unique run identifier."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = uuid4().hex[:8]
    return f"scan_{timestamp}_{suffix}"


async def execute_scan(
    provider: str,
    frameworks: list[str],
    regions: list[str],
    artifacts_dir: Path,
    company_name: str,
) -> dict[str, object]:
    """Execute the CS Kit scan and return metadata."""
    run_id = generate_run_id()

    config = RunConfig(
        provider=provider,  # type: ignore[arg-type]
        frameworks=frameworks,
        regions=regions,
        artifacts_dir=str(artifacts_dir),
    )

    # Suppress rich console output so JSON payload remains clean
    previous_quiet = getattr(cli_console, "quiet", False)
    cli_console.quiet = True  # type: ignore[attr-defined]
    try:
        await _run_scan(config, run_id, output_path=None, company_name=company_name)
    finally:
        cli_console.quiet = previous_quiet  # type: ignore[attr-defined]

    run_dir = artifacts_dir / run_id
    normalized_file = run_dir / "normalized.json"
    summary_file = run_dir / "summary.json"
    metadata_file = run_dir / "metadata.json"

    if not normalized_file.exists():
        raise FileNotFoundError(f"Normalized results not found at {normalized_file}")

    with normalized_file.open("r", encoding="utf-8") as nf:
        normalized_data = json.load(nf)

    summary_data: Optional[dict[str, object]] = None
    if summary_file.exists():
        with summary_file.open("r", encoding="utf-8") as sf:
            summary_data = json.load(sf)

    metadata: Optional[dict[str, object]] = None
    if metadata_file.exists():
        with metadata_file.open("r", encoding="utf-8") as mf:
            metadata = json.load(mf)

    return {
        "run_id": run_id,
        "artifacts_dir": str(run_dir),
        "normalized": normalized_data,
        "summary": summary_data,
        "metadata": metadata,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CS Kit scan service")
    parser.add_argument("--provider", required=True, help="Cloud provider (aws, gcp, azure)")
    parser.add_argument(
        "--frameworks",
        default="",
        help="Comma separated list of compliance frameworks (tool-specific identifiers)",
    )
    parser.add_argument(
        "--regions",
        default="",
        help="Comma separated list of regions (provider specific)",
    )
    parser.add_argument(
        "--artifacts-dir",
        default="./artifacts",
        help="Directory to store scan artifacts",
    )
    parser.add_argument(
        "--company-name",
        default="Security Assessment",
        help="Company name to embed in reports",
    )

    args = parser.parse_args()

    artifacts_dir = Path(args.artifacts_dir).resolve()
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    frameworks = [fw.strip() for fw in args.frameworks.split(",") if fw.strip()]
    regions = [region.strip() for region in args.regions.split(",") if region.strip()]
    if not regions:
        regions = []

    try:
        result = asyncio.run(
            execute_scan(
                provider=args.provider,
                frameworks=frameworks,
                regions=regions,
                artifacts_dir=artifacts_dir,
                company_name=args.company_name,
            )
        )
        json.dump(result, sys.stdout)
    except Exception as exc:  # pylint: disable=broad-except
        error_payload = {"error": str(exc)}
        json.dump(error_payload, sys.stdout)
        sys.exit(1)


if __name__ == "__main__":
    main()

