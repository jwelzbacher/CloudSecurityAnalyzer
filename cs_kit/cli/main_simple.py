"""Simple CLI interface for CS Kit using argparse (no external dependencies)."""

import argparse
import asyncio
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cs_kit.adapters.prowler.run import list_supported_frameworks, run_prowler
from cs_kit.cli.config import RendererConfig, RunConfig
from cs_kit.cli.tool_registry import get_all_supported_providers, select_scanners
from cs_kit.normalizer.mapping import apply_mapping, list_available_mappings
from cs_kit.normalizer.parser import parse_ocsf
from cs_kit.normalizer.summarize import generate_finding_summary
from cs_kit.render.pdf import generate_report


def print_table(headers, rows):
    """Simple table printing without Rich."""
    if not rows:
        return

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    # Print header
    header_line = " | ".join(h.ljust(w) for h, w in zip(headers, widths, strict=False))
    print(header_line)
    print("-" * len(header_line))

    # Print rows
    for row in rows:
        row_line = " | ".join(str(cell).ljust(w) for cell, w in zip(row, widths, strict=False))
        print(row_line)


def cmd_list_frameworks(args):
    """List available compliance frameworks from all sources."""
    print("Available Compliance Frameworks")
    print("=" * 35)

    # Get frameworks from Prowler
    print("\nFrom Prowler:")
    try:
        prowler_frameworks = asyncio.run(list_supported_frameworks())
        if prowler_frameworks:
            rows = [(fw, "prowler") for fw in prowler_frameworks]
            print_table(["Framework ID", "Source"], rows)
        else:
            print("No frameworks found from Prowler")
    except Exception as e:
        print(f"Error getting Prowler frameworks: {e}")

    # Get frameworks from local mappings
    print("\nFrom Local Mappings:")
    try:
        local_frameworks = list_available_mappings()
        if local_frameworks:
            rows = [(fw, "local mapping") for fw in local_frameworks]
            print_table(["Framework ID", "Source"], rows)
        else:
            print("No local framework mappings found")
    except Exception as e:
        print(f"Error getting local frameworks: {e}")


def cmd_list_providers(args):
    """List supported cloud providers."""
    print("Supported Cloud Providers")
    print("=" * 25)

    providers = get_all_supported_providers()
    rows = [(provider.upper(), "✓ Supported") for provider in providers]
    print_table(["Provider", "Status"], rows)


def cmd_run(args):
    """Run security scan and generate report."""

    # Parse input parameters
    frameworks_list = args.frameworks.split(",") if args.frameworks else []
    regions_list = args.regions.split(",") if args.regions else []

    # Generate unique run ID
    run_id = f"scan_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

    # Create configuration
    try:
        config = RunConfig(
            provider=args.provider,
            frameworks=frameworks_list,
            regions=regions_list,
            artifacts_dir=args.artifacts_dir,
            redact_ids=args.redact_ids,
        )
    except Exception as e:
        print(f"Configuration error: {e}")
        sys.exit(1)

    print("=" * 50)
    print("CS Kit Security Scan")
    print("=" * 50)
    print(f"Provider: {args.provider.upper()}")
    print(f"Frameworks: {', '.join(frameworks_list) if frameworks_list else 'None'}")
    print(f"Regions: {', '.join(regions_list) if regions_list else 'All'}")
    print(f"Run ID: {run_id}")
    print("=" * 50)

    try:
        # Run the scan
        asyncio.run(_run_scan(config, run_id, args.output, args.company_name))

    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nScan failed: {e}")
        sys.exit(1)


def cmd_render(args):
    """Generate PDF report from existing normalized findings."""

    input_path = Path(args.input_file)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Input file not found: {args.input_file}")
        sys.exit(1)

    print(f"Generating report from {args.input_file}...")

    try:
        # Load normalized findings
        with open(input_path) as f:
            data = json.load(f)

        findings = []
        if isinstance(data, list):
            # Direct list of findings
            findings = data
        elif isinstance(data, dict) and 'findings' in data:
            # Wrapped in a container
            findings = data['findings']
        else:
            print("Invalid input file format")
            sys.exit(1)

        # Create renderer config
        renderer_config = RendererConfig(
            template_dir=args.template_dir,
            logo_path=args.logo_path,
            company_name=args.company_name,
            include_raw_data=args.include_raw_data,
        )

        # Generate summary
        summary = generate_finding_summary(findings)

        # Generate report
        print("Generating PDF report...")
        generate_report(findings, summary, output_path, renderer_config)

        print(f"Report generated successfully: {output_path}")

    except Exception as e:
        print(f"Failed to generate report: {e}")
        sys.exit(1)


def cmd_validate(args):
    """Validate a configuration file."""

    config_path = Path(args.config_file)
    if not config_path.exists():
        print(f"Configuration file not found: {args.config_file}")
        sys.exit(1)

    try:
        with open(config_path) as f:
            config_data = json.load(f)

        # Validate configuration
        config = RunConfig(**config_data)

        # Validate scanners
        selected_scanners = select_scanners(config)

        print("Configuration is valid!")
        print(f"Provider: {config.provider}")
        print(f"Frameworks: {', '.join(config.frameworks) if config.frameworks else 'None'}")
        print(f"Regions: {', '.join(config.regions) if config.regions else 'All'}")
        print(f"Selected scanners: {', '.join(selected_scanners)}")

    except Exception as e:
        print(f"Configuration validation failed: {e}")
        sys.exit(1)


async def _run_scan(config: RunConfig, run_id: str, output_path: str | None, company_name: str) -> None:
    """Internal function to run the complete scan process."""

    # Create output directories
    artifacts_dir = Path(config.artifacts_dir)
    run_artifacts_dir = artifacts_dir / run_id
    run_artifacts_dir.mkdir(parents=True, exist_ok=True)

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    # Step 1: Select and validate scanners
    print("Validating scanner configuration...")
    selected_scanners = select_scanners(config)

    if not selected_scanners:
        raise ValueError("No scanners selected or available for this provider")

    print(f"✓ Selected scanners: {', '.join(selected_scanners)}")

    # Step 2: Run scanners
    all_scan_files = []

    for scanner in selected_scanners:
        if scanner == "prowler":
            print(f"Running {scanner} scan...")

            # Set up environment variables (user should set these)
            env_vars = dict(os.environ)

            # Run prowler
            scan_files = await run_prowler(
                provider=config.provider,
                frameworks=config.frameworks,
                regions=config.regions,
                env=env_vars,
                out_dir=run_artifacts_dir,
            )

            all_scan_files.extend(scan_files)
            print(f"✓ {scanner} scan completed: {len(scan_files)} files")

    # Step 3: Parse and normalize findings
    print("Parsing and normalizing findings...")

    all_findings = []
    for scan_file in all_scan_files:
        findings = parse_ocsf(scan_file, config.provider, "prowler")
        all_findings.extend(findings)

    print(f"✓ Parsed {len(all_findings)} findings")

    # Step 4: Apply compliance mappings
    if config.frameworks:
        print("Applying compliance mappings...")

        try:
            enriched_findings = apply_mapping(all_findings, config.frameworks)
            print(f"✓ Applied {len(config.frameworks)} framework mappings")
        except Exception as e:
            print(f"Warning: Could not apply some mappings: {e}")
            enriched_findings = all_findings
    else:
        enriched_findings = all_findings

    # Step 5: Generate summary
    print("Generating summary statistics...")
    summary = generate_finding_summary(enriched_findings)

    # Step 6: Save normalized data
    print("Saving normalized data...")

    normalized_file = run_artifacts_dir / "normalized.json"
    with open(normalized_file, 'w') as f:
        json.dump([finding.model_dump() for finding in enriched_findings], f, indent=2, default=str)

    summary_file = run_artifacts_dir / "summary.json"
    with open(summary_file, 'w') as f:
        json.dump(summary.model_dump(), f, indent=2, default=str)

    print(f"✓ Saved normalized data to {normalized_file}")

    # Step 7: Generate PDF report
    if output_path is None:
        output_path = str(reports_dir / f"{run_id}.pdf")

    print("Generating PDF report...")

    renderer_config = RendererConfig(company_name=company_name)
    generate_report(enriched_findings, summary, Path(output_path), renderer_config)

    print(f"✓ Generated PDF report: {output_path}")

    # Display summary
    _display_scan_summary(summary)


def _display_scan_summary(summary) -> None:
    """Display scan summary in a simple format."""

    print("\n" + "=" * 50)
    print("SCAN SUMMARY")
    print("=" * 50)

    # Overall statistics
    print("\nOverall Statistics:")
    print(f"  Total Findings: {summary.total_findings}")
    print(f"  Unique Resources: {summary.unique_resources}")
    print(f"  Unique Accounts: {summary.unique_accounts}")

    # Severity breakdown
    if summary.by_severity:
        print("\nFindings by Severity:")
        for severity, count in summary.by_severity.items():
            print(f"  {severity.title()}: {count}")

    # Status breakdown
    if summary.by_status:
        print("\nFindings by Status:")
        for status, count in summary.by_status.items():
            print(f"  {status.title()}: {count}")

    print("=" * 50)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Cloud Security Testing Kit - Multi-cloud compliance scanning and reporting",
        prog="cs-kit"
    )
    parser.add_argument("--version", action="version", version="CS Kit 0.1.0")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # list-frameworks command
    list_frameworks_parser = subparsers.add_parser(
        "list-frameworks",
        help="List available compliance frameworks from all sources"
    )
    list_frameworks_parser.set_defaults(func=cmd_list_frameworks)

    # list-providers command
    list_providers_parser = subparsers.add_parser(
        "list-providers",
        help="List supported cloud providers"
    )
    list_providers_parser.set_defaults(func=cmd_list_providers)

    # run command
    run_parser = subparsers.add_parser("run", help="Run security scan and generate report")
    run_parser.add_argument("--provider", default="aws", help="Cloud provider (aws, gcp, azure)")
    run_parser.add_argument("--frameworks", help="Comma-separated compliance frameworks")
    run_parser.add_argument("--regions", help="Comma-separated regions to scan")
    run_parser.add_argument("--artifacts-dir", default="./artifacts", help="Directory to store scan artifacts")
    run_parser.add_argument("--output", help="Output PDF file path")
    run_parser.add_argument("--company-name", default="Security Assessment", help="Company name for reports")
    run_parser.add_argument("--redact-ids", action="store_true", default=True, help="Redact sensitive IDs in reports")
    run_parser.add_argument("--no-redact-ids", dest="redact_ids", action="store_false", help="Don't redact sensitive IDs")
    run_parser.set_defaults(func=cmd_run)

    # render command
    render_parser = subparsers.add_parser("render", help="Generate PDF report from existing normalized findings")
    render_parser.add_argument("input_file", help="Path to normalized JSON file")
    render_parser.add_argument("output", help="Output PDF file path")
    render_parser.add_argument("--company-name", default="Security Assessment", help="Company name for reports")
    render_parser.add_argument("--logo-path", help="Path to company logo")
    render_parser.add_argument("--template-dir", help="Custom template directory")
    render_parser.add_argument("--include-raw-data", action="store_true", help="Include raw data in appendix")
    render_parser.set_defaults(func=cmd_render)

    # validate command
    validate_parser = subparsers.add_parser("validate", help="Validate a configuration file")
    validate_parser.add_argument("config_file", help="Path to configuration file")
    validate_parser.set_defaults(func=cmd_validate)

    args = parser.parse_args()

    if not hasattr(args, 'func'):
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
