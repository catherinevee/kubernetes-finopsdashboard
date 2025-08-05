#!/bin/bash

# FinOps Dashboard Deployment Script
# This script builds and deploys the FinOps Dashboard to Kubernetes

set -e

# Configuration
DOCKER_REGISTRY="${DOCKER_REGISTRY:-your-registry.com}"
IMAGE_NAME="${IMAGE_NAME:-finops-dashboard}"
VERSION="${VERSION:-latest}"
NAMESPACE="${NAMESPACE:-finops-dashboard}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-default}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    command -v docker >/dev/null 2>&1 || { error "Docker is required but not installed."; exit 1; }
    command -v kubectl >/dev/null 2>&1 || { error "kubectl is required but not installed."; exit 1; }
    
    # Check if we can connect to Kubernetes
    kubectl cluster-info --context="$KUBECTL_CONTEXT" >/dev/null 2>&1 || {
        error "Cannot connect to Kubernetes cluster with context: $KUBECTL_CONTEXT"
        exit 1
    }
    
    success "Prerequisites check passed"
}

# Build Docker images
build_images() {
    log "Building Docker images..."
    
    # Build main application image
    docker build -t "$DOCKER_REGISTRY/$IMAGE_NAME:$VERSION" .
    docker build -t "$DOCKER_REGISTRY/$IMAGE_NAME-celery:$VERSION" -f Dockerfile.celery .
    
    success "Docker images built successfully"
}

# Push images to registry
push_images() {
    log "Pushing images to registry..."
    
    docker push "$DOCKER_REGISTRY/$IMAGE_NAME:$VERSION"
    docker push "$DOCKER_REGISTRY/$IMAGE_NAME-celery:$VERSION"
    
    success "Images pushed to registry"
}

# Deploy to Kubernetes
deploy_to_k8s() {
    log "Deploying to Kubernetes..."
    
    # Set kubectl context
    kubectl config use-context "$KUBECTL_CONTEXT"
    
    # Update image tags in deployment files
    find k8s/ -name "*.yaml" -exec sed -i "s|finops-dashboard:latest|$DOCKER_REGISTRY/$IMAGE_NAME:$VERSION|g" {} \;
    
    # Apply Kubernetes manifests in order
    kubectl apply -f k8s/00-namespace-config.yaml
    kubectl apply -f k8s/01-postgres.yaml
    kubectl apply -f k8s/02-redis.yaml
    
    # Wait for database to be ready
    log "Waiting for PostgreSQL to be ready..."
    kubectl wait --for=condition=ready pod -l app=postgres -n "$NAMESPACE" --timeout=300s
    
    log "Waiting for Redis to be ready..."
    kubectl wait --for=condition=ready pod -l app=redis -n "$NAMESPACE" --timeout=300s
    
    # Deploy application components
    kubectl apply -f k8s/03-web-app.yaml
    kubectl apply -f k8s/04-celery.yaml
    kubectl apply -f k8s/05-ingress-networking.yaml
    
    # Wait for deployments to be ready
    log "Waiting for web application to be ready..."
    kubectl wait --for=condition=available deployment/finops-web -n "$NAMESPACE" --timeout=600s
    
    log "Waiting for Celery workers to be ready..."
    kubectl wait --for=condition=available deployment/celery-worker -n "$NAMESPACE" --timeout=300s
    
    success "Deployment completed successfully"
}

# Run database migrations
run_migrations() {
    log "Running database migrations..."
    
    # Get the first web pod
    WEB_POD=$(kubectl get pods -n "$NAMESPACE" -l app=finops-web -o jsonpath='{.items[0].metadata.name}')
    
    if [ -z "$WEB_POD" ]; then
        error "No web pods found"
        exit 1
    fi
    
    # Run migrations
    kubectl exec -n "$NAMESPACE" "$WEB_POD" -- python manage.py migrate --noinput
    
    # Create superuser if needed
    kubectl exec -n "$NAMESPACE" "$WEB_POD" -- python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'admin123')
    print('Superuser created')
else:
    print('Superuser already exists')
"
    
    success "Database migrations completed"
}

# Health check
health_check() {
    log "Performing health check..."
    
    # Get service endpoint
    SERVICE_IP=$(kubectl get service finops-web-nodeport -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
    SERVICE_PORT=$(kubectl get service finops-web-nodeport -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].port}')
    
    # Try to access health endpoint
    kubectl run health-check --rm -i --restart=Never --image=curlimages/curl:latest -- \
        curl -f "http://$SERVICE_IP:$SERVICE_PORT/health/" || {
        error "Health check failed"
        exit 1
    }
    
    success "Health check passed"
}

# Display deployment information
show_info() {
    log "Deployment Information:"
    echo "========================"
    echo "Namespace: $NAMESPACE"
    echo "Context: $KUBECTL_CONTEXT"
    echo "Image: $DOCKER_REGISTRY/$IMAGE_NAME:$VERSION"
    echo ""
    
    log "Checking pod status..."
    kubectl get pods -n "$NAMESPACE"
    echo ""
    
    log "Checking service status..."
    kubectl get services -n "$NAMESPACE"
    echo ""
    
    log "Getting ingress information..."
    kubectl get ingress -n "$NAMESPACE"
    echo ""
    
    # Get NodePort for local access
    NODEPORT=$(kubectl get service finops-web-nodeport -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].nodePort}')
    if [ -n "$NODEPORT" ]; then
        log "Application accessible via NodePort: http://localhost:$NODEPORT"
    fi
}

# Cleanup function
cleanup() {
    log "Cleaning up deployment..."
    
    kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
    
    success "Cleanup completed"
}

# Main execution
case "${1:-deploy}" in
    "build")
        check_prerequisites
        build_images
        ;;
    "push")
        check_prerequisites
        build_images
        push_images
        ;;
    "deploy")
        check_prerequisites
        build_images
        push_images
        deploy_to_k8s
        run_migrations
        health_check
        show_info
        ;;
    "migrate")
        run_migrations
        ;;
    "health")
        health_check
        ;;
    "info")
        show_info
        ;;
    "cleanup")
        cleanup
        ;;
    *)
        echo "Usage: $0 {build|push|deploy|migrate|health|info|cleanup}"
        echo ""
        echo "Commands:"
        echo "  build    - Build Docker images only"
        echo "  push     - Build and push Docker images"
        echo "  deploy   - Full deployment (build, push, deploy, migrate, health check)"
        echo "  migrate  - Run database migrations only"
        echo "  health   - Perform health check only"
        echo "  info     - Show deployment information"
        echo "  cleanup  - Remove all deployed resources"
        echo ""
        echo "Environment Variables:"
        echo "  DOCKER_REGISTRY  - Docker registry URL (default: your-registry.com)"
        echo "  IMAGE_NAME       - Image name (default: finops-dashboard)"
        echo "  VERSION          - Image version (default: latest)"
        echo "  NAMESPACE        - Kubernetes namespace (default: finops-dashboard)"
        echo "  KUBECTL_CONTEXT  - Kubectl context (default: default)"
        exit 1
        ;;
esac
