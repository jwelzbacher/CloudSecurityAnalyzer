#!/bin/bash

# CS Kit Docker Run Examples
# Demonstrates various ways to run CS Kit in Docker

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_example() {
    echo -e "${BLUE}Example: $1${NC}"
    echo -e "${GREEN}$2${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${YELLOW}=== $1 ===${NC}"
    echo ""
}

echo "CS Kit Docker Usage Examples"
echo "============================="

print_section "Basic Commands"

print_example "Show help" \
"docker run --rm cs-kit:latest --help"

print_example "List supported providers" \
"docker run --rm cs-kit:latest list-providers"

print_example "List available frameworks" \
"docker run --rm cs-kit:latest list-frameworks"

print_section "Running Scans"

print_example "Basic AWS scan with CIS framework" \
"docker run --rm \\
  -v \$(pwd)/artifacts:/app/artifacts \\
  -v \$(pwd)/reports:/app/reports \\
  -e AWS_ACCESS_KEY_ID=\$AWS_ACCESS_KEY_ID \\
  -e AWS_SECRET_ACCESS_KEY=\$AWS_SECRET_ACCESS_KEY \\
  -e AWS_DEFAULT_REGION=us-east-1 \\
  cs-kit:latest run \\
    --provider aws \\
    --frameworks cis_aws_1_4 \\
    --regions us-east-1,us-west-2"

print_example "GCP scan with multiple frameworks" \
"docker run --rm \\
  -v \$(pwd)/artifacts:/app/artifacts \\
  -v \$(pwd)/reports:/app/reports \\
  -v \$GOOGLE_APPLICATION_CREDENTIALS:/app/gcp-key.json:ro \\
  -e GOOGLE_APPLICATION_CREDENTIALS=/app/gcp-key.json \\
  -e GOOGLE_CLOUD_PROJECT=\$GOOGLE_CLOUD_PROJECT \\
  cs-kit:latest run \\
    --provider gcp \\
    --frameworks cis_gcp_1_3,soc2_type2"

print_example "Azure scan with custom output" \
"docker run --rm \\
  -v \$(pwd)/artifacts:/app/artifacts \\
  -v \$(pwd)/reports:/app/reports \\
  -e AZURE_SUBSCRIPTION_ID=\$AZURE_SUBSCRIPTION_ID \\
  -e AZURE_CLIENT_ID=\$AZURE_CLIENT_ID \\
  -e AZURE_CLIENT_SECRET=\$AZURE_CLIENT_SECRET \\
  -e AZURE_TENANT_ID=\$AZURE_TENANT_ID \\
  cs-kit:latest run \\
    --provider azure \\
    --frameworks cis_azure_1_4 \\
    --output /app/reports/azure-security-report.pdf \\
    --company-name \"My Company\""

print_section "Report Generation"

print_example "Generate PDF from existing scan data" \
"docker run --rm \\
  -v \$(pwd)/artifacts:/app/artifacts \\
  -v \$(pwd)/reports:/app/reports \\
  cs-kit:latest render \\
    /app/artifacts/scan_20240115_103000_abc123/normalized.json \\
    /app/reports/custom-report.pdf \\
    --company-name \"Security Team\""

print_example "Validate configuration file" \
"docker run --rm \\
  -v \$(pwd)/config.json:/app/config.json:ro \\
  cs-kit:latest validate /app/config.json"

print_section "Development and Debugging"

print_example "Interactive development shell" \
"docker run --rm -it \\
  -v \$(pwd):/app \\
  cs-kit:dev"

print_example "Run tests in container" \
"docker run --rm \\
  -v \$(pwd):/app \\
  cs-kit:dev \\
  pytest tests/ -v"

print_example "Development with live code reload" \
"docker run --rm -it \\
  -v \$(pwd):/app \\
  -p 8000:8000 \\
  cs-kit:dev \\
  bash"

print_section "Docker Compose Examples"

print_example "Run with Docker Compose (production)" \
"docker-compose up cs-kit"

print_example "Run with Docker Compose (development)" \
"docker-compose up cs-kit-dev"

print_example "Run specific scan with Docker Compose" \
"docker-compose run --rm cs-kit run --provider aws --frameworks cis_aws_1_4"

print_example "Include Prowler service" \
"docker-compose --profile prowler up"

print_section "Volume Mounting Best Practices"

echo "Key directories to mount:"
echo "• /app/artifacts  - Scan artifacts and normalized data"
echo "• /app/reports    - Generated PDF reports"
echo "• /app/samples    - Sample data and configurations (read-only)"
echo ""

echo "Environment variables to set:"
echo "• AWS: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION"
echo "• GCP: GOOGLE_APPLICATION_CREDENTIALS, GOOGLE_CLOUD_PROJECT"
echo "• Azure: AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID"
echo ""

print_section "Troubleshooting"

print_example "Check container health" \
"docker run --rm cs-kit:latest --version"

print_example "Debug WeasyPrint issues" \
"docker run --rm -it cs-kit:dev python -c \"import weasyprint; print('WeasyPrint OK')\""

print_example "Inspect container contents" \
"docker run --rm -it cs-kit:latest bash"

echo "For more information, see the documentation or run:"
echo "docker run --rm cs-kit:latest --help"