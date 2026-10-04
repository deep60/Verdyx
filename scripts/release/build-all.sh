#!/usr/bin/env bash
# Build all Docker images for a release
# Usage: ./build-all.sh <version>

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    exit 1
fi

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Services to build
SERVICES=(
    "frontend:./frontend:./frontend/Dockerfile"
    "api-gateway:./backend:./backend/api-gateway/Dockerfile"
    "analysis-engine:./backend:./backend/analysis-engine/Dockerfile"
    "bounty-manager:./backend:./backend/bounty-manager/Dockerfile"
    "consensus-service:./backend:./backend/consensus-service/Dockerfile"
    "notification-service:./backend:./backend/notification-service/Dockerfile"
    "payment-service:./backend:./backend/payment-service/Dockerfile"
    "reputation-service:./backend:./backend/reputation-service/Dockerfile"
    "submission-service:./backend:./backend/submission-service/Dockerfile"
    "user-service:./backend:./backend/user-service/Dockerfile"
)

REGISTRY="ghcr.io/deep60"

log_info "Building all services for version $VERSION"

# Setup buildx
docker buildx create --name release-builder --use --driver docker-container 2>/dev/null || \
    docker buildx use release-builder

docker buildx inspect --bootstrap

for service_spec in "${SERVICES[@]}"; do
    IFS=':' read -r service context dockerfile <<< "$service_spec"

    log_info "Building $service..."

    # Build multi-arch
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --tag "${REGISTRY}/verdyx-${service}:${VERSION}" \
        --tag "${REGISTRY}/verdyx-${service}:latest" \
        --file "$dockerfile" \
        --push \
        "$context" \
        --cache-from "type=gha,scope=${service}" \
        --cache-to "type=gha,mode=max,scope=${service}"

    log_info "Built and pushed ${REGISTRY}/verdyx-${service}:${VERSION}"
done

log_info "All services built successfully for version $VERSION"

# Output image digests for cosign signing
for service_spec in "${SERVICES[@]}"; do
    IFS=':' read -r service context dockerfile <<< "$service_spec"
    digest=$(docker buildx imagetools inspect "${REGISTRY}/verdyx-${service}:${VERSION}" --format '{{json .Manifest.Digest}}' | jq -r '.[0]')
    echo "${REGISTRY}/verdyx-${service}@${digest}" > "image-digest-${service}.txt"
done