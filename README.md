# CS Kit - Cloud Security Testing Kit

A comprehensive cloud security testing toolkit that supports multiple cloud providers (AWS, GCP, Azure) and compliance frameworks. Built with Prowler and other open source security tools.

## Features

- Multi-cloud security scanning (AWS, GCP, Azure)
- Multiple compliance framework support (CIS, NIST, SOC2, etc.)
- OCSF-compliant data normalization
- PDF report generation with professional templates
- CLI and API interfaces
- Extensible adapter system for security tools

## Quick Start

### Prerequisites

- Python 3.12+
- Poetry for dependency management
- Prowler CLI tool (installed separately)

### Installation

#### Local Development
```bash
# Clone the repository
git clone <repository-url>
cd cs_kit

# Install dependencies
poetry install

# Install development dependencies
make dev

# Run tests
make test
```

#### Docker (Recommended)
```bash
# Build the Docker images
./scripts/docker-build.sh --all

# Quick test
docker run --rm cs-kit:latest --help

# Run with Docker Compose
docker-compose up cs-kit-dev
```

For detailed Docker usage, see [DOCKER.md](DOCKER.md).

### Basic Usage

#### Local CLI
```bash
# List available compliance frameworks
poetry run cs-kit list-frameworks

# Run security scan on AWS
poetry run cs-kit run --provider aws --frameworks cis_aws_1_4 --regions us-east-1,us-west-2

# Generate PDF report from existing scan results
poetry run cs-kit render artifacts/scan_123/normalized.json report.pdf
```

#### Docker
```bash
# List providers
docker run --rm cs-kit:latest list-providers

# Run AWS scan (requires credentials)
docker run --rm \
  -v $(pwd)/artifacts:/app/artifacts \
  -v $(pwd)/reports:/app/reports \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  cs-kit:latest run --provider aws --frameworks cis_aws_1_4

# Generate report
docker run --rm \
  -v $(pwd)/artifacts:/app/artifacts \
  -v $(pwd)/reports:/app/reports \
  cs-kit:latest render /app/artifacts/scan_123/normalized.json /app/reports/report.pdf
```

## Development

### Available Make Targets

- `make dev` - Install development dependencies and pre-commit hooks
- `make test` - Run tests with coverage
- `make lint` - Run ruff linter
- `make type` - Run mypy type checker
- `make format` - Format code with black and ruff
- `make clean` - Clean build artifacts

### Project Structure

```
cs_kit/
├── adapters/           # Tool adapters (prowler, etc.)
├── normalizer/         # OCSF data normalization
├── mappings/           # Compliance framework mappings
├── render/             # PDF report generation
│   └── templates/      # Jinja2 HTML templates
├── cli/                # Command line interface
└── tests/              # Test suite
```

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=cs_kit --cov-report=html

# Run specific test file
poetry run pytest tests/test_config.py
```

### Code Quality

This project uses several tools to maintain code quality:

- **Ruff**: Fast Python linter and formatter
- **MyPy**: Static type checking
- **Black**: Code formatting
- **Pre-commit**: Git hooks for code quality
- **Pytest**: Testing framework

## License Compliance

This toolkit is designed for commercial use. All integrated open source tools have been reviewed for license compatibility:

- **Prowler**: Apache 2.0 License ✅ (Commercial use allowed)
- **WeasyPrint**: BSD License ✅ (Commercial use allowed)
- **Jinja2**: BSD License ✅ (Commercial use allowed)
- **Pydantic**: MIT License ✅ (Commercial use allowed)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting: `make test lint type`
5. Submit a pull request

## Architecture

The toolkit follows a modular architecture:

1. **Adapters**: Interface with security scanning tools
2. **Normalizer**: Convert tool outputs to OCSF format
3. **Mappings**: Map findings to compliance frameworks
4. **Renderer**: Generate professional PDF reports
5. **CLI**: Command-line interface for all operations

## Supported Providers

- ✅ Amazon Web Services (AWS)
- ✅ Google Cloud Platform (GCP)
- ✅ Microsoft Azure

## Supported Frameworks

- CIS (Center for Internet Security)
- NIST Cybersecurity Framework
- SOC 2
- ISO 27001
- Custom frameworks (via YAML configuration)
- Test Edit
