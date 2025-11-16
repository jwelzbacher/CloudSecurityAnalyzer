"""Flask web application for CS Kit."""

import asyncio
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

from cs_kit.adapters.prowler.run import list_supported_frameworks, run_prowler
from cs_kit.cli.config import RunConfig
from cs_kit.cli.tool_registry import get_all_supported_providers, select_scanners
from cs_kit.normalizer.mapping import apply_mapping, list_available_mappings
from cs_kit.normalizer.parser import parse_ocsf
from cs_kit.normalizer.summarize import generate_finding_summary

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max file size

# Store scan results in memory (in production, use a database or cache)
scan_results: dict[str, dict] = {}


def get_frameworks_by_provider(provider: str) -> list[str]:
    """Get available frameworks for a provider.

    Args:
        provider: Cloud provider (aws, gcp, azure)

    Returns:
        List of framework IDs
    """
    try:
        # Get frameworks from Prowler
        prowler_frameworks = asyncio.run(list_supported_frameworks())

        # Filter by provider
        provider_frameworks = [
            fw for fw in prowler_frameworks
            if fw.endswith(f"_{provider}") or provider in fw
        ]

        # Also get local mappings
        local_frameworks = list_available_mappings()

        # Combine and deduplicate
        all_frameworks = list(set(provider_frameworks + local_frameworks))
        return sorted(all_frameworks)
    except Exception:
        # Fallback to known frameworks
        known_frameworks = {
            "aws": ["cis_1.4_aws", "cis_1.5_aws", "cis_2.0_aws", "soc2_aws",
                   "nist_csf_1.1_aws", "pci_4.0_aws", "iso27001_2022_aws",
                   "hipaa_aws", "gdpr_aws"],
            "gcp": ["cis_2.0_gcp", "cis_3.0_gcp", "soc2_gcp", "iso27001_2022_gcp"],
            "azure": ["cis_2.0_azure", "cis_2.1_azure", "soc2_azure",
                      "iso27001_2022_azure"],
        }
        return known_frameworks.get(provider, [])


@app.route("/")
def index():
    """Main page with scan form."""
    providers = get_all_supported_providers()
    return render_template("index.html", providers=providers)


@app.route("/api/frameworks/<provider>")
def get_frameworks(provider: str):
    """Get available frameworks for a provider."""
    if provider not in get_all_supported_providers():
        return jsonify({"error": f"Unsupported provider: {provider}"}), 400

    frameworks = get_frameworks_by_provider(provider)
    return jsonify({"frameworks": frameworks})


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Start a security scan."""
    try:
        data = request.json
        provider = data.get("provider")
        access_key_id = data.get("access_key_id")
        secret_access_key = data.get("secret_access_key")
        frameworks = data.get("frameworks", [])
        regions = data.get("regions", [])

        # Validate inputs
        if not provider or provider not in get_all_supported_providers():
            return jsonify({"error": "Invalid provider"}), 400

        if not access_key_id or not secret_access_key:
            return jsonify({"error": "Access keys are required"}), 400

        if not frameworks:
            return jsonify({"error": "At least one framework must be selected"}), 400

        # Generate scan ID
        scan_id = f"scan_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

        # Store scan status
        scan_results[scan_id] = {
            "status": "running",
            "provider": provider,
            "frameworks": frameworks,
            "regions": regions,
            "started_at": datetime.now(UTC).isoformat(),
        }

        # Run scan asynchronously
        asyncio.create_task(run_scan_async(
            scan_id=scan_id,
            provider=provider,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            frameworks=frameworks,
            regions=regions,
        ))

        return jsonify({
            "scan_id": scan_id,
            "status": "running",
            "message": "Scan started successfully"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


async def run_scan_async(
    scan_id: str,
    provider: str,
    access_key_id: str,
    secret_access_key: str,
    frameworks: list[str],
    regions: list[str],
):
    """Run scan asynchronously."""
    try:
        # Set up environment variables
        env_vars = {
            **os.environ,
            "AWS_ACCESS_KEY_ID": access_key_id,
            "AWS_SECRET_ACCESS_KEY": secret_access_key,
            "AWS_DEFAULT_REGION": regions[0] if regions else "us-east-1",
        }

        # Add provider-specific env vars
        if provider == "gcp":
            env_vars["GOOGLE_APPLICATION_CREDENTIALS"] = access_key_id
        elif provider == "azure":
            env_vars["AZURE_CLIENT_ID"] = access_key_id
            env_vars["AZURE_CLIENT_SECRET"] = secret_access_key

        # Create output directory
        artifacts_dir = Path("./artifacts")
        run_artifacts_dir = artifacts_dir / scan_id
        run_artifacts_dir.mkdir(parents=True, exist_ok=True)

        # Create config
        config = RunConfig(
            provider=provider,  # type: ignore
            frameworks=frameworks,
            regions=regions,
            artifacts_dir=str(artifacts_dir),
        )

        # Select scanners
        selected_scanners = select_scanners(config)
        if not selected_scanners:
            raise ValueError("No scanners available for this provider")

        # Run scanners
        all_scan_files = []
        for scanner in selected_scanners:
            if scanner == "prowler":
                scan_files = await run_prowler(
                    provider=config.provider,
                    frameworks=config.frameworks,
                    regions=config.regions,
                    env=env_vars,
                    out_dir=run_artifacts_dir,
                )
                all_scan_files.extend(scan_files)

        # Parse findings
        all_findings = []
        for scan_file in all_scan_files:
            findings = parse_ocsf(scan_file, config.provider, "prowler")
            all_findings.extend(findings)

        # Apply mappings
        enriched_findings = all_findings
        if config.frameworks:
            try:
                enriched_findings = apply_mapping(all_findings, config.frameworks)
            except Exception:
                pass  # Use unmapped findings if mapping fails

        # Generate summary
        summary = generate_finding_summary(enriched_findings)

        # Save results
        normalized_file = run_artifacts_dir / "normalized.json"
        with open(normalized_file, "w") as f:
            json.dump(
                [finding.model_dump() for finding in enriched_findings],
                f,
                indent=2,
                default=str,
            )

        summary_file = run_artifacts_dir / "summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary.model_dump(), f, indent=2, default=str)

        # Update scan results
        scan_results[scan_id].update({
            "status": "completed",
            "findings_count": len(enriched_findings),
            "summary": summary.model_dump(),
            "artifacts_dir": str(run_artifacts_dir),
            "normalized_file": str(normalized_file),
            "summary_file": str(summary_file),
            "completed_at": datetime.now(UTC).isoformat(),
        })

    except Exception as e:
        scan_results[scan_id].update({
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.now(UTC).isoformat(),
        })


@app.route("/api/scan/<scan_id>")
def get_scan_status(scan_id: str):
    """Get scan status and results."""
    if scan_id not in scan_results:
        return jsonify({"error": "Scan not found"}), 404

    result = scan_results[scan_id].copy()

    # Don't expose credentials
    result.pop("access_key_id", None)
    result.pop("secret_access_key", None)

    return jsonify(result)


@app.route("/scan/<scan_id>")
def view_scan_results(scan_id: str):
    """View scan results in pretty HTML format."""
    if scan_id not in scan_results:
        return "Scan not found", 404

    scan_data = scan_results[scan_id]

    if scan_data["status"] != "completed":
        return render_template(
            "scan_status.html",
            scan_id=scan_id,
            status=scan_data["status"],
            error=scan_data.get("error"),
        )

    # Load findings
    normalized_file = Path(scan_data["normalized_file"])
    if not normalized_file.exists():
        return "Results file not found", 404

    with open(normalized_file) as f:
        findings = json.load(f)

    summary = scan_data.get("summary", {})

    return render_template(
        "results.html",
        scan_id=scan_id,
        findings=findings,
        summary=summary,
        provider=scan_data["provider"],
        frameworks=scan_data["frameworks"],
        regions=scan_data["regions"],
    )


@app.route("/api/scan/<scan_id>/download")
def download_results(scan_id: str):
    """Download normalized JSON results."""
    if scan_id not in scan_results:
        return jsonify({"error": "Scan not found"}), 404

    scan_data = scan_results[scan_id]
    if scan_data["status"] != "completed":
        return jsonify({"error": "Scan not completed"}), 400

    normalized_file = Path(scan_data["normalized_file"])
    if not normalized_file.exists():
        return jsonify({"error": "Results file not found"}), 404

    return send_file(
        normalized_file,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"{scan_id}_results.json",
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

