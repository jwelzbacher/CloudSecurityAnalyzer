"""Prowler security scanner adapter."""

import asyncio
import os
import shutil
import subprocess
from pathlib import Path
from typing import Literal

from cs_kit.adapters.prowler.exceptions import ProwlerError, ProwlerNotFoundError


async def run_prowler(
    provider: Literal["aws", "gcp", "azure"],
    frameworks: list[str],
    regions: list[str],
    env: dict[str, str],
    out_dir: Path,
) -> list[Path]:
    """Run prowler for the given provider.

    Produces one or more JSON files in OCSF-like format in out_dir and returns their paths.

    Args:
        provider: Cloud provider to scan
        frameworks: Compliance frameworks to apply
        regions: Regions to scan (provider-specific)
        env: Environment variables for the prowler process
        out_dir: Output directory for results

    Returns:
        List of paths to generated JSON files

    Raises:
        ProwlerNotFoundError: If prowler is not found on PATH
        ProwlerError: If prowler execution fails
    """
    # Check if prowler is available
    if not shutil.which("prowler"):
        raise ProwlerNotFoundError(
            "prowler not found on PATH. Please install prowler CLI tool."
        )

    # Create provider-specific output directory
    provider_out_dir = out_dir / "scanner=prowler" / f"provider={provider}"
    provider_out_dir.mkdir(parents=True, exist_ok=True)

    # Build list of compliance IDs to run (prowler only accepts one at a time)
    compliance_ids = frameworks if frameworks else [None]
    json_files: list[Path] = []
    existing_files = {path.resolve() for path in provider_out_dir.glob("*.json")}

    for compliance in compliance_ids:
        cmd = _build_prowler_command(provider, compliance, regions, provider_out_dir)

        try:
            result = await _run_prowler_subprocess(cmd, env)
            # Exit code 3 is normal for Prowler when findings are detected (not an error)
            if result.returncode != 0 and result.returncode != 3:
                raise ProwlerError(
                    f"Prowler execution failed with return code {result.returncode}: "
                    f"{result.stderr}"
                )
        except FileNotFoundError as e:
            raise ProwlerNotFoundError(f"Failed to execute prowler: {e}") from e

        new_files = [
            path
            for path in provider_out_dir.glob("*.json")
            if path.resolve() not in existing_files
        ]
        json_files.extend(new_files)
        existing_files.update(path.resolve() for path in new_files)

    if not json_files:
        raise ProwlerError(
            f"No JSON output files found in {provider_out_dir}. "
            f"Prowler may not have generated expected output format."
        )

    return json_files


def _build_prowler_command(
    provider: Literal["aws", "gcp", "azure"],
    compliance: str | None,
    regions: list[str],
    out_dir: Path,
) -> list[str]:
    """Build prowler command based on provider and parameters.

    Args:
        provider: Cloud provider
        frameworks: Compliance frameworks
        regions: Regions to scan
        out_dir: Output directory

    Returns:
        Command list for subprocess
    """
    cmd = ["prowler", provider]

    # Add output format
    cmd.extend(["-M", "json-ocsf"])

    # Add output directory
    cmd.extend(["-o", str(out_dir)])

    # Provider-specific options
    if provider == "aws":
        if regions:
            cmd.extend(["-f", ",".join(regions)])
        if compliance:
            cmd.extend(["--compliance", compliance])
    elif provider == "gcp":
        if compliance:
            cmd.extend(["--compliance", compliance])
    elif provider == "azure":
        if compliance:
            cmd.extend(["--compliance", compliance])

    return cmd


async def _run_prowler_subprocess(
    cmd: list[str], env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Run prowler subprocess asynchronously.

    Args:
        cmd: Command to execute
        env: Environment variables

    Returns:
        Completed process result
    """
    # Merge provided env with current environment
    full_env = {**os.environ, **env}

    # Run the subprocess
    process = await asyncio.create_subprocess_exec(
        *cmd,
        env=full_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await process.communicate()

    return subprocess.CompletedProcess(
        args=cmd,
        returncode=process.returncode or 0,
        stdout=stdout.decode() if stdout else "",
        stderr=stderr.decode() if stderr else "",
    )


async def list_supported_frameworks() -> list[str]:
    """List compliance frameworks supported by prowler.

    Returns:
        List of framework IDs

    Raises:
        ProwlerNotFoundError: If prowler is not found
        ProwlerError: If prowler execution fails
    """
    if not shutil.which("prowler"):
        raise ProwlerNotFoundError(
            "prowler not found on PATH. Please install prowler CLI tool."
        )

    cmd = ["prowler", "--list-compliance"]

    try:
        result = await _run_prowler_subprocess(cmd, {})
        if result.returncode != 0:
            raise ProwlerError(
                f"Failed to list compliance frameworks: {result.stderr}"
            )

        # Parse the output to extract framework IDs
        frameworks = _parse_compliance_list(result.stdout)
        return frameworks

    except FileNotFoundError as e:
        raise ProwlerNotFoundError(f"Failed to execute prowler: {e}") from e


def _parse_compliance_list(output: str) -> list[str]:
    """Parse prowler compliance list output.

    Args:
        output: Raw prowler output

    Returns:
        List of framework IDs
    """
    frameworks = []
    lines = output.strip().split("\n")

    for line in lines:
        line = line.strip()
        if line and not line.startswith("Available") and not line.startswith("---"):
            # Extract framework ID from line (assumes format like "cis_aws_1_4: Description")
            if ":" in line:
                framework_id = line.split(":", 1)[0].strip()
                if framework_id:
                    frameworks.append(framework_id)

    return frameworks


async def validate_prowler_installation() -> dict[str, str]:
    """Validate prowler installation and return version info.

    Returns:
        Dictionary with version and installation info

    Raises:
        ProwlerNotFoundError: If prowler is not found
    """
    if not shutil.which("prowler"):
        raise ProwlerNotFoundError(
            "prowler not found on PATH. Please install prowler CLI tool."
        )

    try:
        # Get version info
        result = await _run_prowler_subprocess(["prowler", "--version"], {})
        version = result.stdout.strip() if result.stdout else "unknown"

        # Get installation path
        prowler_path = shutil.which("prowler") or "unknown"

        return {
            "version": version,
            "path": prowler_path,
            "status": "available",
        }

    except Exception as e:
        raise ProwlerError(f"Failed to validate prowler installation: {e}") from e
