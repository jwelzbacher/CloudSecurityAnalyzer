"""Main CLI interface for CS Kit."""

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from cs_kit.adapters.prowler.run import list_supported_frameworks, run_prowler
from cs_kit.cli.config import RendererConfig, RunConfig
from cs_kit.cli.tool_registry import get_all_supported_providers, select_scanners
from cs_kit.normalizer.mapping import apply_mapping, list_available_mappings
from cs_kit.normalizer.parser import parse_ocsf
from cs_kit.normalizer.summarize import generate_finding_summary
from cs_kit.render.pdf import generate_report

# Initialize Typer app and Rich console
app = typer.Typer(
    name="cs-kit",
    help="Cloud Security Testing Kit - Multi-cloud compliance scanning and reporting",
    add_completion=False,
)
console = Console()


@app.command("list-frameworks")
def list_frameworks() -> None:
    """List available compliance frameworks from all sources."""
    console.print("[bold blue]Available Compliance Frameworks[/bold blue]")
    
    # Get frameworks from Prowler
    console.print("\n[yellow]From Prowler:[/yellow]")
    try:
        prowler_frameworks = asyncio.run(list_supported_frameworks())
        if prowler_frameworks:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Framework ID", style="cyan")
            table.add_column("Source", style="green")
            
            for framework in prowler_frameworks:
                table.add_row(framework, "prowler")
            
            console.print(table)
        else:
            console.print("[red]No frameworks found from Prowler[/red]")
    except Exception as e:
        console.print(f"[red]Error getting Prowler frameworks: {e}[/red]")
    
    # Get frameworks from local mappings
    console.print("\n[yellow]From Local Mappings:[/yellow]")
    try:
        local_frameworks = list_available_mappings()
        if local_frameworks:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Framework ID", style="cyan")
            table.add_column("Source", style="green")
            
            for framework in local_frameworks:
                table.add_row(framework, "local mapping")
            
            console.print(table)
        else:
            console.print("[red]No local framework mappings found[/red]")
    except Exception as e:
        console.print(f"[red]Error getting local frameworks: {e}[/red]")


@app.command("list-providers")
def list_providers() -> None:
    """List supported cloud providers."""
    console.print("[bold blue]Supported Cloud Providers[/bold blue]")
    
    providers = get_all_supported_providers()
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Provider", style="cyan")
    table.add_column("Status", style="green")
    
    for provider in providers:
        table.add_row(provider.upper(), "✓ Supported")
    
    console.print(table)


@app.command()
def run(
    provider: str = "aws",
    frameworks: Optional[str] = None,
    regions: Optional[str] = None,
    artifacts_dir: str = "./artifacts",
    output: Optional[str] = None,
    company_name: str = "Security Assessment",
    redact_ids: bool = True,
) -> None:
    """Run security scan and generate report."""
    
    # Parse input parameters
    frameworks_list = frameworks.split(",") if frameworks else []
    regions_list = regions.split(",") if regions else []
    
    # Generate unique run ID
    run_id = f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    
    # Create configuration
    config = RunConfig(
        provider=provider,  # type: ignore
        frameworks=frameworks_list,
        regions=regions_list,
        artifacts_dir=artifacts_dir,
        redact_ids=redact_ids,
    )
    
    console.print(Panel(
        f"[bold green]Starting Security Scan[/bold green]\n"
        f"Provider: {provider.upper()}\n"
        f"Frameworks: {', '.join(frameworks_list) if frameworks_list else 'None'}\n"
        f"Regions: {', '.join(regions_list) if regions_list else 'All'}\n"
        f"Run ID: {run_id}",
        title="CS Kit Scan"
    ))
    
    try:
        # Run the scan
        asyncio.run(_run_scan(config, run_id, output, company_name))
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[red]Scan failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def render(
    input_file: str,
    output: str,
    company_name: str = "Security Assessment",
    logo_path: Optional[str] = None,
    template_dir: Optional[str] = None,
    include_raw_data: bool = False,
) -> None:
    """Generate PDF report from existing normalized findings."""
    
    input_path = Path(input_file)
    output_path = Path(output)
    
    if not input_path.exists():
        console.print(f"[red]Input file not found: {input_file}[/red]")
        raise typer.Exit(1)
    
    console.print(f"[blue]Generating report from {input_file}...[/blue]")
    
    try:
        # Load normalized findings
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        findings = []
        if isinstance(data, list):
            # Direct list of findings
            findings = data
        elif isinstance(data, dict) and 'findings' in data:
            # Wrapped in a container
            findings = data['findings']
        else:
            console.print("[red]Invalid input file format[/red]")
            raise typer.Exit(1)
        
        # Create renderer config
        renderer_config = RendererConfig(
            template_dir=template_dir,
            logo_path=logo_path,
            company_name=company_name,
            include_raw_data=include_raw_data,
        )
        
        # Generate summary
        summary = generate_finding_summary(findings)
        
        # Generate report
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("Generating PDF report...", total=None)
            generate_report(findings, summary, output_path, renderer_config)
        
        console.print(f"[green]Report generated successfully: {output_path}[/green]")
        
    except Exception as e:
        console.print(f"[red]Failed to generate report: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def validate(
    config_file: str,
) -> None:
    """Validate a configuration file."""
    
    config_path = Path(config_file)
    if not config_path.exists():
        console.print(f"[red]Configuration file not found: {config_file}[/red]")
        raise typer.Exit(1)
    
    try:
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        # Validate configuration
        config = RunConfig(**config_data)
        
        # Validate scanners
        selected_scanners = select_scanners(config)
        
        console.print("[green]Configuration is valid![/green]")
        console.print(f"Provider: {config.provider}")
        console.print(f"Frameworks: {', '.join(config.frameworks) if config.frameworks else 'None'}")
        console.print(f"Regions: {', '.join(config.regions) if config.regions else 'All'}")
        console.print(f"Selected scanners: {', '.join(selected_scanners)}")
        
    except Exception as e:
        console.print(f"[red]Configuration validation failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Show version information."""
    from cs_kit import __version__
    
    console.print(f"[bold blue]CS Kit[/bold blue] version [green]{__version__}[/green]")
    console.print("Cloud Security Testing Kit")
    console.print("Multi-cloud compliance scanning and reporting")


async def _run_scan(config: RunConfig, run_id: str, output_path: Optional[str], company_name: str) -> None:
    """Internal function to run the complete scan process."""
    
    # Create output directories
    artifacts_dir = Path(config.artifacts_dir)
    run_artifacts_dir = artifacts_dir / run_id
    run_artifacts_dir.mkdir(parents=True, exist_ok=True)
    
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Step 1: Select and validate scanners
        progress.add_task("Validating scanner configuration...", total=None)
        selected_scanners = select_scanners(config)
        
        if not selected_scanners:
            raise ValueError("No scanners selected or available for this provider")
        
        console.print(f"[green]Selected scanners: {', '.join(selected_scanners)}[/green]")
        
        # Step 2: Run scanners
        all_scan_files = []
        
        for scanner in selected_scanners:
            if scanner == "prowler":
                task = progress.add_task(f"Running {scanner} scan...", total=None)
                
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
                progress.remove_task(task)
                console.print(f"[green]✓ {scanner} scan completed: {len(scan_files)} files[/green]")
        
        # Step 3: Parse and normalize findings
        task = progress.add_task("Parsing and normalizing findings...", total=None)
        
        all_findings = []
        for scan_file in all_scan_files:
            findings = parse_ocsf(scan_file, config.provider, "prowler")
            all_findings.extend(findings)
        
        progress.remove_task(task)
        console.print(f"[green]✓ Parsed {len(all_findings)} findings[/green]")
        
        # Step 4: Apply compliance mappings
        if config.frameworks:
            task = progress.add_task("Applying compliance mappings...", total=None)
            
            try:
                enriched_findings = apply_mapping(all_findings, config.frameworks)
                progress.remove_task(task)
                console.print(f"[green]✓ Applied {len(config.frameworks)} framework mappings[/green]")
            except Exception as e:
                progress.remove_task(task)
                console.print(f"[yellow]Warning: Could not apply some mappings: {e}[/yellow]")
                enriched_findings = all_findings
        else:
            enriched_findings = all_findings
        
        # Step 5: Generate summary
        task = progress.add_task("Generating summary statistics...", total=None)
        summary = generate_finding_summary(enriched_findings)
        progress.remove_task(task)
        
        # Step 6: Save normalized data
        task = progress.add_task("Saving normalized data...", total=None)
        
        normalized_file = run_artifacts_dir / "normalized.json"
        with open(normalized_file, 'w') as f:
            json.dump([finding.model_dump() for finding in enriched_findings], f, indent=2, default=str)
        
        summary_file = run_artifacts_dir / "summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary.model_dump(), f, indent=2, default=str)
        
        progress.remove_task(task)
        console.print(f"[green]✓ Saved normalized data to {normalized_file}[/green]")
        
        # Step 7: Generate PDF report
        if output_path is None:
            output_path = str(reports_dir / f"{run_id}.pdf")
        
        task = progress.add_task("Generating PDF report...", total=None)
        
        renderer_config = RendererConfig(company_name=company_name)
        generate_report(enriched_findings, summary, Path(output_path), renderer_config)
        
        progress.remove_task(task)
        console.print(f"[green]✓ Generated PDF report: {output_path}[/green]")
    
    # Display summary
    _display_scan_summary(summary, enriched_findings)


def _display_scan_summary(summary, findings) -> None:
    """Display scan summary in a nice table."""
    
    console.print("\n[bold blue]Scan Summary[/bold blue]")
    
    # Overall statistics
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="green")
    
    table.add_row("Total Findings", str(summary.total_findings))
    table.add_row("Unique Resources", str(summary.unique_resources))
    table.add_row("Unique Accounts", str(summary.unique_accounts))
    
    console.print(table)
    
    # Severity breakdown
    if summary.by_severity:
        console.print("\n[bold yellow]Findings by Severity[/bold yellow]")
        severity_table = Table(show_header=True, header_style="bold magenta")
        severity_table.add_column("Severity", style="cyan")
        severity_table.add_column("Count", justify="right", style="green")
        
        for severity, count in summary.by_severity.items():
            severity_table.add_row(severity.title(), str(count))
        
        console.print(severity_table)
    
    # Status breakdown
    if summary.by_status:
        console.print("\n[bold yellow]Findings by Status[/bold yellow]")
        status_table = Table(show_header=True, header_style="bold magenta")
        status_table.add_column("Status", style="cyan")
        status_table.add_column("Count", justify="right", style="green")
        
        for status, count in summary.by_status.items():
            status_table.add_row(status.title(), str(count))
        
        console.print(status_table)


if __name__ == "__main__":
    app()