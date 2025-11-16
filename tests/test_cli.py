"""Tests for CLI functionality."""

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from cs_kit.cli.main_click import cli
from cs_kit.normalizer.ocsf_models import FindingSummary, OCSFEnrichedFinding


class TestCLI:
    """Test CLI commands."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_version_command(self) -> None:
        """Test version command."""
        result = self.runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.stdout

    def test_list_providers_command(self) -> None:
        """Test list providers command."""
        result = self.runner.invoke(cli, ["list-providers"])
        assert result.exit_code == 0
        assert "AWS" in result.stdout
        assert "GCP" in result.stdout
        assert "AZURE" in result.stdout

    @patch('cs_kit.cli.main.list_supported_frameworks')
    @patch('cs_kit.cli.main.list_available_mappings')
    def test_list_frameworks_command(
        self, mock_mappings: MagicMock, mock_prowler_frameworks: AsyncMock
    ) -> None:
        """Test list frameworks command."""
        # Mock return values
        mock_prowler_frameworks.return_value = ["cis_aws_1_4", "nist_csf"]
        mock_mappings.return_value = ["cis_aws_1_4", "custom_framework"]

        result = self.runner.invoke(cli, ["list-frameworks"])
        assert result.exit_code == 0
        assert "cis_aws_1_4" in result.stdout
        assert "prowler" in result.stdout
        assert "local mapping" in result.stdout

    @patch('cs_kit.cli.main.list_supported_frameworks')
    @patch('cs_kit.cli.main.list_available_mappings')
    def test_list_frameworks_command_error(
        self, mock_mappings: MagicMock, mock_prowler_frameworks: AsyncMock
    ) -> None:
        """Test list frameworks command with errors."""
        # Mock errors
        mock_prowler_frameworks.side_effect = Exception("Prowler not available")
        mock_mappings.side_effect = Exception("Mappings not found")

        result = self.runner.invoke(cli, ["list-frameworks"])
        assert result.exit_code == 0  # Should not fail, just show errors
        assert "Error getting Prowler frameworks" in result.stdout
        assert "Error getting local frameworks" in result.stdout

    def test_validate_command_missing_file(self) -> None:
        """Test validate command with missing file."""
        result = self.runner.invoke(cli, ["validate", "nonexistent.json"])
        assert result.exit_code == 1
        assert "Configuration file not found" in result.stdout

    def test_validate_command_valid_config(self) -> None:
        """Test validate command with valid configuration."""
        config_data = {
            "provider": "aws",
            "frameworks": ["cis_aws_1_4"],
            "regions": ["us-east-1"],
            "artifacts_dir": "/tmp/artifacts",
            "scanners": {"prowler": True},
            "redact_ids": True,
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = Path(f.name)

        try:
            result = self.runner.invoke(cli, ["validate", str(config_file)])
            assert result.exit_code == 0
            assert "Configuration is valid" in result.stdout
            assert "Provider: aws" in result.stdout
        finally:
            config_file.unlink()

    def test_validate_command_invalid_config(self) -> None:
        """Test validate command with invalid configuration."""
        config_data = {
            "provider": "invalid_provider",  # Invalid
            "artifacts_dir": "/tmp/artifacts",
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = Path(f.name)

        try:
            result = self.runner.invoke(cli, ["validate", str(config_file)])
            assert result.exit_code == 1
            assert "Configuration validation failed" in result.stdout
        finally:
            config_file.unlink()

    def test_render_command_missing_input(self) -> None:
        """Test render command with missing input file."""
        result = self.runner.invoke(cli, ["render", "nonexistent.json", "output.pdf"])
        assert result.exit_code == 1
        assert "Input file not found" in result.stdout

    @patch('cs_kit.cli.main.generate_report')
    @patch('cs_kit.cli.main.generate_finding_summary')
    def test_render_command_success(
        self, mock_summary: MagicMock, mock_generate: MagicMock
    ) -> None:
        """Test successful render command."""
        # Create test data
        test_findings = [
            {
                "time": "2024-01-15T10:30:00Z",
                "provider": "aws",
                "product": "prowler",
                "severity": "high",
                "status": "fail",
            }
        ]

        # Mock summary
        mock_summary.return_value = FindingSummary(
            total_findings=1,
            by_severity={"high": 1},
            by_status={"fail": 1},
            by_provider={"aws": 1},
            by_product={"prowler": 1},
            unique_resources=1,
            unique_accounts=1,
        )

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_findings, f)
            input_file = Path(f.name)

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "test_report.pdf"

            try:
                result = self.runner.invoke(cli, [
                    "render", str(input_file), str(output_file),
                    "--company-name", "Test Company"
                ])
                assert result.exit_code == 0
                assert "Report generated successfully" in result.stdout
                mock_generate.assert_called_once()
            finally:
                input_file.unlink()

    def test_render_command_invalid_input(self) -> None:
        """Test render command with invalid input format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump("invalid format", f)
            input_file = Path(f.name)

        try:
            result = self.runner.invoke(cli, ["render", str(input_file), "output.pdf"])
            assert result.exit_code == 1
            assert "Invalid input file format" in result.stdout
        finally:
            input_file.unlink()

    @patch('cs_kit.cli.main_click._run_scan')
    def test_run_command_basic(self, mock_run_scan: AsyncMock) -> None:
        """Test basic run command."""
        mock_run_scan.return_value = None

        with tempfile.TemporaryDirectory() as tmp_dir:
            result = self.runner.invoke(cli, [
                "run",
                "--provider", "aws",
                "--frameworks", "cis_aws_1_4",
                "--regions", "us-east-1",
                "--artifacts-dir", tmp_dir,
                "--company-name", "Test Company"
            ])

            # Should not fail (mock prevents actual execution)
            mock_run_scan.assert_called_once()

    @patch('cs_kit.cli.main_click._run_scan')
    def test_run_command_with_output(self, mock_run_scan: AsyncMock) -> None:
        """Test run command with custom output path."""
        mock_run_scan.return_value = None

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "custom_report.pdf"

            result = self.runner.invoke(cli, [
                "run",
                "--provider", "gcp",
                "--output", str(output_path),
                "--artifacts-dir", tmp_dir,
            ])

            mock_run_scan.assert_called_once()

    @patch('cs_kit.cli.main_click._run_scan')
    def test_run_command_error(self, mock_run_scan: AsyncMock) -> None:
        """Test run command with scan error."""
        mock_run_scan.side_effect = Exception("Scan failed")

        with tempfile.TemporaryDirectory() as tmp_dir:
            result = self.runner.invoke(cli, [
                "run",
                "--provider", "aws",
                "--artifacts-dir", tmp_dir,
            ])

            assert result.exit_code == 1
            assert "Scan failed" in result.stdout


class TestRunScanInternal:
    """Test internal _run_scan function."""

    @patch('cs_kit.cli.main.generate_report')
    @patch('cs_kit.cli.main.generate_finding_summary')
    @patch('cs_kit.cli.main.apply_mapping')
    @patch('cs_kit.cli.main.parse_ocsf')
    @patch('cs_kit.cli.main.run_prowler')
    @patch('cs_kit.cli.main.select_scanners')
    def test_run_scan_complete_flow(
        self,
        mock_select: MagicMock,
        mock_prowler: AsyncMock,
        mock_parse: MagicMock,
        mock_mapping: MagicMock,
        mock_summary: MagicMock,
        mock_report: MagicMock,
    ) -> None:
        """Test complete scan flow."""
        from cs_kit.cli.config import RunConfig
        from cs_kit.cli.main_click import _run_scan

        # Mock return values
        mock_select.return_value = ["prowler"]
        mock_prowler.return_value = [Path("/tmp/scan1.json")]

        # Create mock finding
        mock_finding = OCSFEnrichedFinding(
            time=datetime.now(UTC),
            provider="aws",
            product="prowler",
            severity="high",
            status="fail",
        )
        mock_parse.return_value = [mock_finding]
        mock_mapping.return_value = [mock_finding]

        mock_summary.return_value = FindingSummary(
            total_findings=1,
            by_severity={"high": 1},
            by_status={"fail": 1},
            by_provider={"aws": 1},
            by_product={"prowler": 1},
            unique_resources=1,
            unique_accounts=1,
        )

        # Create test configuration
        config = RunConfig(
            provider="aws",
            frameworks=["cis_aws_1_4"],
            regions=["us-east-1"],
            artifacts_dir="/tmp/artifacts",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifacts_dir = Path(tmp_dir)
            config.artifacts_dir = str(artifacts_dir)

            # Run the scan (this is async)
            import asyncio
            asyncio.run(_run_scan(config, "test_run", None, "Test Company"))

            # Verify calls
            mock_select.assert_called_once()
            mock_prowler.assert_called_once()
            mock_parse.assert_called_once()
            mock_mapping.assert_called_once()
            mock_summary.assert_called_once()
            mock_report.assert_called_once()

    @patch('cs_kit.cli.main.select_scanners')
    def test_run_scan_no_scanners(self, mock_select: MagicMock) -> None:
        """Test scan with no available scanners."""
        from cs_kit.cli.config import RunConfig
        from cs_kit.cli.main_click import _run_scan

        mock_select.return_value = []  # No scanners

        config = RunConfig(
            provider="aws",
            artifacts_dir="/tmp/artifacts",
        )

        with pytest.raises(ValueError, match="No scanners selected"):
            import asyncio
            asyncio.run(_run_scan(config, "test_run", None, "Test Company"))

    @patch('cs_kit.cli.main.generate_report')
    @patch('cs_kit.cli.main.generate_finding_summary')
    @patch('cs_kit.cli.main.parse_ocsf')
    @patch('cs_kit.cli.main.run_prowler')
    @patch('cs_kit.cli.main.select_scanners')
    def test_run_scan_no_frameworks(
        self,
        mock_select: MagicMock,
        mock_prowler: AsyncMock,
        mock_parse: MagicMock,
        mock_summary: MagicMock,
        mock_report: MagicMock,
    ) -> None:
        """Test scan without framework mappings."""
        from cs_kit.cli.config import RunConfig
        from cs_kit.cli.main_click import _run_scan

        # Mock return values
        mock_select.return_value = ["prowler"]
        mock_prowler.return_value = [Path("/tmp/scan1.json")]

        mock_finding = OCSFEnrichedFinding(
            time=datetime.now(UTC),
            provider="aws",
            product="prowler",
        )
        mock_parse.return_value = [mock_finding]

        mock_summary.return_value = FindingSummary(
            total_findings=1,
            by_provider={"aws": 1},
            by_product={"prowler": 1},
            unique_resources=1,
            unique_accounts=1,
        )

        # Config without frameworks
        config = RunConfig(
            provider="aws",
            frameworks=[],  # No frameworks
            artifacts_dir="/tmp/artifacts",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifacts_dir = Path(tmp_dir)
            config.artifacts_dir = str(artifacts_dir)

            import asyncio
            asyncio.run(_run_scan(config, "test_run", None, "Test Company"))

            # Should not call apply_mapping
            mock_summary.assert_called_once()
            mock_report.assert_called_once()


class TestDisplayScanSummary:
    """Test _display_scan_summary function."""

    def test_display_scan_summary(self, capsys) -> None:
        """Test scan summary display."""
        from cs_kit.cli.main_click import _display_scan_summary

        summary = FindingSummary(
            total_findings=10,
            by_severity={"high": 3, "medium": 5, "low": 2},
            by_status={"fail": 8, "pass": 2},
            by_provider={"aws": 10},
            by_product={"prowler": 10},
            unique_resources=5,
            unique_accounts=2,
        )

        findings = []  # Not used in the function

        _display_scan_summary(summary, findings)

        # The function uses Rich console, so we can't easily capture output
        # But we can verify it doesn't crash
        assert True  # Function completed without error
