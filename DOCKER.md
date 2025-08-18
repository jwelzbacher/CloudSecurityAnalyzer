# CS Kit Docker Guide

This guide explains how to build, run, and deploy CS Kit using Docker containers.

## Overview

CS Kit provides Docker support with:
- **Multi-stage builds** for optimized production images
- **Development containers** with full tooling
- **Docker Compose** for easy orchestration
- **Pre-built scripts** for common operations

## Quick Start

### 1. Build the Images

```bash
# Build production image
./scripts/docker-build.sh --prod

# Build development image  
./scripts/docker-build.sh --dev

# Build both images
./scripts/docker-build.sh --all
```

### 2. Run a Basic Scan

```bash
# List supported providers
docker run --rm cs-kit:latest list-providers

# Run AWS scan (requires AWS credentials)
docker run --rm \
  -v $(pwd)/artifacts:/app/artifacts \
  -v $(pwd)/reports:/app/reports \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  cs-kit:latest run --provider aws --frameworks cis_aws_1_4
```

### 3. Use Docker Compose

```bash
# Run with Docker Compose
docker-compose up cs-kit

# Development mode
docker-compose up cs-kit-dev
```

## Docker Images

### Production Image (`cs-kit:latest`)

- **Base**: Python 3.12 slim
- **Size**: ~200-300MB (optimized)
- **Purpose**: Production deployments
- **Includes**: 
  - CS Kit application
  - WeasyPrint and dependencies
  - Runtime libraries only
- **User**: Non-root user (cskit)

### Development Image (`cs-kit:dev`)

- **Base**: Same as production + dev tools
- **Size**: ~400-500MB
- **Purpose**: Development and testing
- **Includes**:
  - All production components
  - Development dependencies
  - Testing tools (pytest, coverage)
  - Code quality tools (ruff, mypy)
  - Debugging utilities

## Building Images

### Using Build Script

```bash
# Production only
./scripts/docker-build.sh --prod

# Development only  
./scripts/docker-build.sh --dev

# Both images
./scripts/docker-build.sh --all

# Custom tag
./scripts/docker-build.sh --prod --tag v1.0.0

# Build and push to registry
./scripts/docker-build.sh --all --push --tag v1.0.0
```

### Manual Docker Build

```bash
# Production image
docker build --target production -t cs-kit:latest .

# Development image
docker build --target development -t cs-kit:dev .
```

## Running Containers

### Basic Commands

```bash
# Show help
docker run --rm cs-kit:latest --help

# List providers
docker run --rm cs-kit:latest list-providers

# List frameworks
docker run --rm cs-kit:latest list-frameworks
```

### Cloud Provider Scans

#### AWS Scan

```bash
docker run --rm \
  -v $(pwd)/artifacts:/app/artifacts \
  -v $(pwd)/reports:/app/reports \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION=us-east-1 \
  cs-kit:latest run \
    --provider aws \
    --frameworks cis_aws_1_4 \
    --regions us-east-1,us-west-2 \
    --company-name "My Company"
```

#### GCP Scan

```bash
docker run --rm \
  -v $(pwd)/artifacts:/app/artifacts \
  -v $(pwd)/reports:/app/reports \
  -v $GOOGLE_APPLICATION_CREDENTIALS:/app/gcp-key.json:ro \
  -e GOOGLE_APPLICATION_CREDENTIALS=/app/gcp-key.json \
  -e GOOGLE_CLOUD_PROJECT=$GOOGLE_CLOUD_PROJECT \
  cs-kit:latest run \
    --provider gcp \
    --frameworks cis_gcp_1_3
```

#### Azure Scan

```bash
docker run --rm \
  -v $(pwd)/artifacts:/app/artifacts \
  -v $(pwd)/reports:/app/reports \
  -e AZURE_SUBSCRIPTION_ID=$AZURE_SUBSCRIPTION_ID \
  -e AZURE_CLIENT_ID=$AZURE_CLIENT_ID \
  -e AZURE_CLIENT_SECRET=$AZURE_CLIENT_SECRET \
  -e AZURE_TENANT_ID=$AZURE_TENANT_ID \
  cs-kit:latest run \
    --provider azure \
    --frameworks cis_azure_1_4
```

### Report Generation

```bash
# Generate PDF from existing scan data
docker run --rm \
  -v $(pwd)/artifacts:/app/artifacts \
  -v $(pwd)/reports:/app/reports \
  cs-kit:latest render \
    /app/artifacts/scan_20240115_103000_abc123/normalized.json \
    /app/reports/custom-report.pdf \
    --company-name "Security Team"
```

## Docker Compose

### Services

The `docker-compose.yml` includes:

- **cs-kit**: Production service
- **cs-kit-dev**: Development service  
- **prowler**: Optional Prowler service (with `--profile prowler`)

### Usage

```bash
# Start production service
docker-compose up cs-kit

# Start development service
docker-compose up cs-kit-dev

# Run one-off command
docker-compose run --rm cs-kit list-providers

# Include Prowler service
docker-compose --profile prowler up
```

### Environment Variables

Create a `.env` file for credentials:

```env
# AWS
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1

# GCP
GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
GOOGLE_CLOUD_PROJECT=your-project-id

# Azure
AZURE_SUBSCRIPTION_ID=your_subscription_id
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret
AZURE_TENANT_ID=your_tenant_id
```

## Development

### Interactive Development

```bash
# Start development container with shell
docker run --rm -it \
  -v $(pwd):/app \
  cs-kit:dev

# Or with Docker Compose
docker-compose run --rm cs-kit-dev
```

### Running Tests

```bash
# Run all tests
docker run --rm -v $(pwd):/app cs-kit:dev pytest

# Run specific test file
docker run --rm -v $(pwd):/app cs-kit:dev pytest tests/test_cli.py -v

# Run with coverage
docker run --rm -v $(pwd):/app cs-kit:dev pytest --cov=cs_kit
```

### Code Quality

```bash
# Run linting
docker run --rm -v $(pwd):/app cs-kit:dev ruff check .

# Run type checking
docker run --rm -v $(pwd):/app cs-kit:dev mypy cs_kit/

# Format code
docker run --rm -v $(pwd):/app cs-kit:dev black .
```

## Volume Mounts

### Required Volumes

- `/app/artifacts`: Scan artifacts and normalized data
- `/app/reports`: Generated PDF reports

### Optional Volumes

- `/app/samples`: Sample configurations (read-only)
- `/app`: Full source code (development only)

### Example

```bash
docker run --rm \
  -v $(pwd)/artifacts:/app/artifacts \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/samples:/app/samples:ro \
  cs-kit:latest [command]
```

## Security Considerations

### Non-Root User

Both production and development images run as non-root user `cskit` (UID 1000) for security.

### Credential Management

- Never embed credentials in images
- Use environment variables or mounted files
- Consider using cloud provider IAM roles when possible

### Network Security

- Images expose no ports by default
- Use Docker networks for service communication
- Consider using secrets management for production

## Troubleshooting

### Common Issues

#### WeasyPrint Dependencies

```bash
# Test WeasyPrint installation
docker run --rm cs-kit:latest python -c "import weasyprint; print('OK')"
```

#### Permission Issues

```bash
# Check file permissions
docker run --rm -v $(pwd):/app cs-kit:dev ls -la /app/

# Fix ownership (if needed)
sudo chown -R $USER:$USER artifacts/ reports/
```

#### Missing Cloud Credentials

```bash
# Verify AWS credentials
docker run --rm -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID cs-kit:latest \
  python -c "import boto3; print(boto3.Session().get_credentials())"
```

### Debug Mode

```bash
# Interactive shell in production image
docker run --rm -it cs-kit:latest bash

# Check installed packages
docker run --rm cs-kit:latest pip list

# Check system dependencies
docker run --rm cs-kit:latest apt list --installed
```

## Deployment

### Registry Push

```bash
# Tag for registry
docker tag cs-kit:latest your-registry.com/cs-kit:latest

# Push to registry
docker push your-registry.com/cs-kit:latest
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cs-kit
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cs-kit
  template:
    metadata:
      labels:
        app: cs-kit
    spec:
      containers:
      - name: cs-kit
        image: cs-kit:latest
        command: ["cs-kit"]
        args: ["run", "--provider", "aws", "--frameworks", "cis_aws_1_4"]
        env:
        - name: AWS_ACCESS_KEY_ID
          valueFrom:
            secretKeyRef:
              name: aws-credentials
              key: access-key-id
        volumeMounts:
        - name: artifacts
          mountPath: /app/artifacts
        - name: reports
          mountPath: /app/reports
      volumes:
      - name: artifacts
        emptyDir: {}
      - name: reports
        emptyDir: {}
```

## Performance Optimization

### Image Size

- Production image uses multi-stage builds
- Development dependencies excluded from production
- Unnecessary files removed via `.dockerignore`

### Build Cache

```bash
# Use BuildKit for better caching
DOCKER_BUILDKIT=1 docker build .

# Build with cache from registry
docker build --cache-from cs-kit:latest .
```

### Resource Limits

```bash
# Limit memory usage
docker run --rm --memory=1g cs-kit:latest [command]

# Limit CPU usage  
docker run --rm --cpus=0.5 cs-kit:latest [command]
```

## Examples Script

Run `./scripts/docker-run-examples.sh` to see comprehensive usage examples.

## Support

For issues with Docker deployment:

1. Check the troubleshooting section above
2. Verify your Docker version is recent (20.10+)
3. Ensure sufficient disk space for images
4. Check Docker daemon logs for build issues