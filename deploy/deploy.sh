#!/usr/bin/env bash
# ==============================================================================
# Deploy Script for DependencySec on Azure VM
# Dedicated Compose project: dependencysec
# ==============================================================================

set -euo pipefail

DEPLOY_DIR="${1:-/opt/dependencysec-analyzer}"
IMAGE_NAME="${2:-dependencysec-analyzer}"
IMAGE_TAG="${3:-latest}"
ACR_REGISTRY="${4:-}"
ACR_USER="${5:-}"
APP_PORT="${6:-8001}"

# Accept ACR_PASSWORD strictly through environment; never pass via command arguments
ACR_PASSWORD="${ACR_PASSWORD:-}"

COMPOSE_PROJECT="dependencysec"

echo "=========================================================="
echo " Starting deployment of ${IMAGE_NAME}:${IMAGE_TAG}"
echo " Deployment Directory:   ${DEPLOY_DIR}"
echo " Compose Project:        ${COMPOSE_PROJECT}"
echo " Application Host Port:  ${APP_PORT}"
echo " Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "=========================================================="

# Create deployment directory if not exists
mkdir -p "${DEPLOY_DIR}"
cd "${DEPLOY_DIR}"

# Login to Azure Container Registry securely if credentials provided
if [ -n "${ACR_REGISTRY}" ] && [ -n "${ACR_USER}" ] && [ -n "${ACR_PASSWORD}" ]; then
    echo "Logging into Azure Container Registry: ${ACR_REGISTRY}..."
    printf '%s' "${ACR_PASSWORD}" | docker login "${ACR_REGISTRY}" -u "${ACR_USER}" --password-stdin
fi
unset ACR_PASSWORD

# Detect docker compose command (support both 'docker compose' and 'docker-compose')
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
else
    echo "ERROR: Neither 'docker compose' nor 'docker-compose' found on target VM."
    exit 1
fi

COMPOSE_CMD="${DOCKER_COMPOSE} -p ${COMPOSE_PROJECT}"
echo "Using compose command: ${COMPOSE_CMD}"

# Create/Update .env file for docker-compose
cat <<EOF > "${DEPLOY_DIR}/.env"
IMAGE_NAME=${IMAGE_NAME}
IMAGE_TAG=${IMAGE_TAG}
APP_PORT=${APP_PORT}
PYTHONUNBUFFERED=1
EOF

# Ensure SQLite database file exists only if missing; never overwrite an existing database
DB_FILE="${DEPLOY_DIR}/devsecops.db"
if [ ! -e "${DB_FILE}" ]; then
    echo "Database file does not exist. Initializing empty database file: ${DB_FILE}..."
    touch "${DB_FILE}"
    chmod 666 "${DB_FILE}"
fi

# Validate that the database path is a regular file
if [ ! -f "${DB_FILE}" ]; then
    echo "ERROR: Database path '${DB_FILE}' exists but is not a regular file!"
    exit 1
fi

# Pull exact image tag built by Jenkins
echo "Pulling exact Docker image: ${IMAGE_NAME}:${IMAGE_TAG}..."
${COMPOSE_CMD} pull dependencysec-analyzer

# Launch only the dependencysec-analyzer service without affecting other containers
echo "Recreating and launching dependencysec-analyzer service..."
${COMPOSE_CMD} up -d --no-deps --force-recreate dependencysec-analyzer

# Wait for container startup and health check
echo "Waiting for service to become healthy at http://127.0.0.1:${APP_PORT}/api/health..."
MAX_ATTEMPTS=15
ATTEMPT=1
SERVER_HEALTHY=0

while [ ${ATTEMPT} -le ${MAX_ATTEMPTS} ]; do
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${APP_PORT}/api/health" || echo "000")
    if [ "${HTTP_STATUS}" -eq 200 ]; then
        echo "Health check passed! HTTP ${HTTP_STATUS} OK (Attempt ${ATTEMPT})"
        SERVER_HEALTHY=1
        break
    else
        echo "Waiting for app to respond... Attempt ${ATTEMPT}/${MAX_ATTEMPTS} (Status: ${HTTP_STATUS})"
        sleep 3
        ATTEMPT=$((ATTEMPT + 1))
    fi
done

if [ ${SERVER_HEALTHY} -ne 1 ]; then
    echo "ERROR: Deployment failed health check! Container logs:"
    ${COMPOSE_CMD} logs --tail=50 dependencysec-analyzer
    exit 1
fi

echo "=========================================================="
echo " Deployment SUCCESSFUL! DependencySec is running on port ${APP_PORT}."
echo " Existing containers on other ports were preserved untouched."
echo "=========================================================="
