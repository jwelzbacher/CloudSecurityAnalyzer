# syntax=docker/dockerfile:1

# CS Kit - Cloud Security Testing Kit
# Multi-stage build to minimize final image size

ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Build stage - Install system dependencies and Python packages
FROM base as builder

# Install system dependencies needed for building Python packages and WeasyPrint
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials for compiling Python packages
    build-essential \
    gcc \
    g++ \
    # WeasyPrint system dependencies
    libcairo2-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    # Additional dependencies that might be needed
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    libpng-dev \
    zlib1g-dev \
    # Git for potential package installations
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy dependency files
WORKDIR /build
COPY pyproject.toml poetry.lock ./

# Install Poetry and dependencies
RUN pip install poetry==1.8.2 && \
    poetry config virtualenvs.create false && \
    poetry install --only=main --no-root

# Production stage - Create final runtime image
FROM base as production

# Install only runtime dependencies for WeasyPrint
RUN apt-get update && apt-get install -y --no-install-recommends \
    # WeasyPrint runtime dependencies
    libcairo2 \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi8 \
    shared-mime-info \
    # Additional runtime libraries
    libxml2 \
    libxslt1.1 \
    libjpeg62-turbo \
    libpng16-16 \
    zlib1g \
    # Utilities that might be useful
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user for security
RUN groupadd --gid 1000 cskit && \
    useradd --uid 1000 --gid cskit --shell /bin/bash --create-home cskit

# Set up application directory
WORKDIR /app
RUN chown cskit:cskit /app

# Copy application code
COPY --chown=cskit:cskit . .

# Install the application in development mode
RUN pip install -e .

# Create directories for artifacts and reports
RUN mkdir -p /app/artifacts /app/reports && \
    chown -R cskit:cskit /app/artifacts /app/reports

# Switch to non-root user
USER cskit

# Health check to verify the application is working
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD cs-kit --version || exit 1

# Set default command
ENTRYPOINT ["cs-kit"]
CMD ["--help"]

# Development stage - Includes development dependencies and tools
FROM builder as development

# Install development dependencies
RUN poetry install --with=dev --no-root

# Install additional development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Development and debugging tools
    vim \
    nano \
    htop \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for development
RUN groupadd --gid 1000 cskit && \
    useradd --uid 1000 --gid cskit --shell /bin/bash --create-home cskit

WORKDIR /app
RUN chown cskit:cskit /app

# Copy application code
COPY --chown=cskit:cskit . .

# Install the application in development mode
RUN pip install -e .

# Create directories
RUN mkdir -p /app/artifacts /app/reports && \
    chown -R cskit:cskit /app/artifacts /app/reports

USER cskit

# Default to interactive shell for development
CMD ["/bin/bash"]