#!/usr/bin/env bash
# Setup test databases for each backend service
# This script creates isolated databases per service and runs their migrations
# Exports DATABASE_URLs to .ci-test-db-env for use in subsequent CI steps

set -euo pipefail

# Configuration
PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-test_user}"
PGPASSWORD="${PGPASSWORD:-test_password}"
BASE_DB="verdyx_test"

# Services that need isolated databases
SERVICES=(
    "analysis"
    "bounty"
    "consensus"
    "notification"
    "payment"
    "reputation"
    "submission"
    "user"
)

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Export PGPASSWORD for psql
export PGPASSWORD

# Create base database if it doesn't exist
log_info "Creating base database: $BASE_DB"
psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c "CREATE DATABASE $BASE_DB;" 2>/dev/null || true

# Create per-service databases and run migrations
ENV_FILE="${GITHUB_WORKSPACE:-$(pwd)}/.ci-test-db-env"
> "$ENV_FILE"  # Clear the file

for service in "${SERVICES[@]}"; do
    DB_NAME="${BASE_DB}_${service}"
    log_info "Setting up database for $service: $DB_NAME"

    # Create database
    psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$BASE_DB" -c "CREATE DATABASE $DB_NAME;" 2>/dev/null || true

    # Run migrations for this service
    SERVICE_DIR="${GITHUB_WORKSPACE:-$(pwd)}/backend/${service}-engine"
    if [[ "$service" == "analysis" ]]; then
        SERVICE_DIR="${GITHUB_WORKSPACE:-$(pwd)}/backend/analysis-engine"
    elif [[ "$service" == "user" ]]; then
        SERVICE_DIR="${GITHUB_WORKSPACE:-$(pwd)}/backend/user-service"
    elif [[ "$service" == "submission" ]]; then
        SERVICE_DIR="${GITHUB_WORKSPACE:-$(pwd)}/backend/submission-service"
    elif [[ "$service" == "bounty" ]]; then
        SERVICE_DIR="${GITHUB_WORKSPACE:-$(pwd)}/backend/bounty-manager"
    elif [[ "$service" == "consensus" ]]; then
        SERVICE_DIR="${GITHUB_WORKSPACE:-$(pwd)}/backend/consensus-service"
    elif [[ "$service" == "notification" ]]; then
        SERVICE_DIR="${GITHUB_WORKSPACE:-$(pwd)}/backend/notification-service"
    elif [[ "$service" == "payment" ]]; then
        SERVICE_DIR="${GITHUB_WORKSPACE:-$(pwd)}/backend/payment-service"
    elif [[ "$service" == "reputation" ]]; then
        SERVICE_DIR="${GITHUB_WORKSPACE:-$(pwd)}/backend/reputation-service"
    fi

    if [[ -d "$SERVICE_DIR/migrations" ]]; then
        log_info "Running migrations for $service from $SERVICE_DIR/migrations"
        cd "$SERVICE_DIR"
        DATABASE_URL="postgresql://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/${DB_NAME}" \
            sqlx migrate run --source migrations 2>&1 | tail -20
    else
        log_warn "No migrations directory found for $service at $SERVICE_DIR/migrations"
    fi

    # Export DATABASE_URL for this service
    VAR_NAME="${service^^}_DATABASE_URL"
    if [[ "$service" == "analysis" ]]; then
        VAR_NAME="ANALYSIS_ENGINE_DATABASE_URL"
    elif [[ "$service" == "bounty" ]]; then
        VAR_NAME="BOUNTY_MANAGER_DATABASE_URL"
    elif [[ "$service" == "consensus" ]]; then
        VAR_NAME="CONSENSUS_SERVICE_DATABASE_URL"
    elif [[ "$service" == "notification" ]]; then
        VAR_NAME="NOTIFICATION_SERVICE_DATABASE_URL"
    elif [[ "$service" == "payment" ]]; then
        VAR_NAME="PAYMENT_SERVICE_DATABASE_URL"
    elif [[ "$service" == "reputation" ]]; then
        VAR_NAME="REPUTATION_SERVICE_DATABASE_URL"
    elif [[ "$service" == "submission" ]]; then
        VAR_NAME="SUBMISSION_SERVICE_DATABASE_URL"
    elif [[ "$service" == "user" ]]; then
        VAR_NAME="USER_SERVICE_DATABASE_URL"
    fi

    echo "${VAR_NAME}=postgresql://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/${DB_NAME}" >> "$ENV_FILE"
done

# Also export the base DATABASE_URL
echo "DATABASE_URL=postgresql://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/${BASE_DB}" >> "$ENV_FILE"

log_info "Test databases setup complete. Environment file: $ENV_FILE"
cat "$ENV_FILE"