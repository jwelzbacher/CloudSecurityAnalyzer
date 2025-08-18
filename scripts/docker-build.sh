#!/bin/bash

# CS Kit Docker Build Script
# Builds Docker images for production and development

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Default values
BUILD_PRODUCTION=true
BUILD_DEVELOPMENT=false
PUSH_IMAGES=false
IMAGE_TAG="latest"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dev|--development)
            BUILD_DEVELOPMENT=true
            shift
            ;;
        --prod|--production)
            BUILD_PRODUCTION=true
            shift
            ;;
        --all)
            BUILD_PRODUCTION=true
            BUILD_DEVELOPMENT=true
            shift
            ;;
        --push)
            PUSH_IMAGES=true
            shift
            ;;
        --tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dev, --development    Build development image"
            echo "  --prod, --production    Build production image (default)"
            echo "  --all                   Build both production and development images"
            echo "  --push                  Push images to registry after building"
            echo "  --tag TAG               Tag for the images (default: latest)"
            echo "  --help, -h              Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

print_status "Starting CS Kit Docker build process..."

# Build production image
if [ "$BUILD_PRODUCTION" = true ]; then
    print_status "Building production image..."
    
    if docker build --target production -t "cs-kit:${IMAGE_TAG}" -t "cs-kit:production" .; then
        print_success "Production image built successfully!"
        
        # Show image size
        IMAGE_SIZE=$(docker images --format "table {{.Size}}" cs-kit:${IMAGE_TAG} | tail -n 1)
        print_status "Production image size: $IMAGE_SIZE"
        
        if [ "$PUSH_IMAGES" = true ]; then
            print_status "Pushing production image..."
            docker push "cs-kit:${IMAGE_TAG}"
            docker push "cs-kit:production"
            print_success "Production image pushed!"
        fi
    else
        print_error "Failed to build production image!"
        exit 1
    fi
fi

# Build development image
if [ "$BUILD_DEVELOPMENT" = true ]; then
    print_status "Building development image..."
    
    if docker build --target development -t "cs-kit:dev" -t "cs-kit:development" .; then
        print_success "Development image built successfully!"
        
        # Show image size
        IMAGE_SIZE=$(docker images --format "table {{.Size}}" cs-kit:dev | tail -n 1)
        print_status "Development image size: $IMAGE_SIZE"
        
        if [ "$PUSH_IMAGES" = true ]; then
            print_status "Pushing development image..."
            docker push "cs-kit:dev"
            docker push "cs-kit:development"
            print_success "Development image pushed!"
        fi
    else
        print_error "Failed to build development image!"
        exit 1
    fi
fi

print_success "Docker build process completed!"

# Show available images
print_status "Available CS Kit images:"
docker images | grep cs-kit | head -5

print_status "To run the application:"
echo "  Production:  docker run --rm cs-kit:${IMAGE_TAG} --help"
echo "  Development: docker run --rm -it cs-kit:dev"
echo "  Or use:      docker-compose up cs-kit"