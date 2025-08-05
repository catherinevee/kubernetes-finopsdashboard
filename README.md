# FinOps Dashboard - Comprehensive AWS FinOps CLI Web Interface

## Overview

The FinOps Dashboard is a comprehensive, secure Python web application that provides an enterprise-grade graphical interface to the AWS FinOps Dashboard CLI tool. Built with Django 4.2+, it offers OAuth2/JWT authentication, multi-factor authentication (MFA), role-based access control, background task processing with Celery, comprehensive audit logging, and a responsive Bootstrap 5 interface.

## Features

### 🔐 Security
- **OAuth2/JWT Authentication** with django-oauth-toolkit
- **Multi-Factor Authentication (MFA)** with django-otp
- **Role-Based Access Control (RBAC)** with custom permissions
- **Account Lockout Protection** after failed login attempts
- **Comprehensive Audit Logging** with security incident detection
- **Command Injection Prevention** with secure CLI wrapper
- **Input Validation** using Pydantic models
- **Security Headers** and Content Security Policy (CSP)
- **Rate Limiting** for API endpoints and authentication

### 🚀 Architecture
- **Django 4.2+** with PostgreSQL database
- **Celery** with Redis for background task processing
- **Bootstrap 5** responsive UI (no Tailwind CSS)
- **RESTful API** with comprehensive endpoints
- **Docker** containerization with security best practices
- **Kubernetes** deployment with comprehensive manifests
- **Nginx** reverse proxy with SSL termination

### 📊 AWS FinOps Integration
- **Secure CLI Wrapper** for AWS FinOps Dashboard commands
- **AWS Profiles Management** with encrypted credential storage
- **Background Task Processing** for long-running CLI operations
- **Real-time Progress Tracking** with WebSocket support
- **Command History** and audit trail
- **Resource Usage Monitoring** and cost analysis

### 🛠 Operations
- **Health Check Endpoints** for Kubernetes probes
- **Comprehensive Logging** with structured log format
- **Metrics Collection** for monitoring and alerting
- **Automated Backups** and disaster recovery
- **Performance Monitoring** with resource usage tracking

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Kubernetes cluster (for production deployment)
- Python 3.11+ (for local development)
- PostgreSQL 15+
- Redis 7+

### Local Development with Docker Compose

1. **Clone and setup environment:**
```bash
git clone <repository-url>
cd kubernetes-finopsdashboard
cp .env.template .env
# Edit .env with your configuration
```

2. **Start services:**
```bash
docker-compose up -d
```

3. **Run initial setup:**
```bash
# Run migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Collect static files
docker-compose exec web python manage.py collectstatic --noinput
```

4. **Access the application:**
- Web Interface: http://localhost:8000
- Admin Interface: http://localhost:8000/admin
- Health Check: http://localhost:8000/health/

### Production Deployment with Kubernetes

1. **Build and push images:**
```bash
# Set environment variables
export DOCKER_REGISTRY=your-registry.com
export VERSION=1.0.0

# Build and push
./deploy.sh push
```

2. **Configure Kubernetes secrets:**
```bash
# Update base64 encoded secrets in k8s/00-namespace-config.yaml
echo -n "your-secret-key" | base64
```

3. **Deploy to Kubernetes:**
```bash
./deploy.sh deploy
```

4. **Verify deployment:**
```bash
./deploy.sh info
./deploy.sh health
```

## Application Structure

```
finops_dashboard/
├── apps/
│   ├── authentication/     # OAuth2/MFA authentication
│   ├── profiles/          # AWS profiles management
│   ├── tasks/            # Background task processing
│   ├── audit/            # Security audit logging
│   ├── dashboard/        # Main dashboard interface
│   ├── core/            # Core utilities and health checks
│   └── api/             # RESTful API endpoints
├── templates/           # Bootstrap 5 HTML templates
├── static/             # CSS, JavaScript, images
├── k8s/               # Kubernetes deployment manifests
├── nginx/             # Nginx configuration
├── requirements.txt   # Python dependencies
├── docker-compose.yml # Local development setup
└── deploy.sh         # Deployment automation script
```

## Security Best Practices

### Authentication & Authorization
- OAuth2/JWT tokens with configurable expiration
- Multi-factor authentication (TOTP/SMS)
- Role-based permissions with least privilege principle
- Account lockout after failed attempts
- Session management with secure cookies

### Command Execution Security
- **Never uses `shell=True`** in subprocess calls
- Input validation with whitelist patterns
- Parameter arrays instead of string concatenation
- Timeout enforcement and resource limits
- Comprehensive logging of all CLI operations

### Data Protection
- Encrypted credential storage using Django's encryption
- Secure handling of AWS access keys and secrets
- PII data protection with field-level encryption
- Audit trail for all data access and modifications

### Infrastructure Security
- Non-root container execution
- Read-only root filesystem
- Security contexts and capabilities dropping
- Network policies for pod-to-pod communication
- TLS/SSL encryption for all communications

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEBUG` | Enable debug mode | `False` |
| `SECRET_KEY` | Django secret key | *Required* |
| `DATABASE_URL` | PostgreSQL connection string | *Required* |
| `CELERY_BROKER_URL` | Redis connection for Celery | *Required* |
| `OAUTH2_CLIENT_SECRET` | OAuth2 client secret | *Required* |
| `MFA_REQUIRED` | Enforce MFA for all users | `True` |
| `RATE_LIMIT_LOGIN` | Login rate limit | `5/m` |
| `SESSION_TIMEOUT` | Session timeout in seconds | `3600` |

## Deployment Options

### Docker Compose (Development)
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f web

# Scale Celery workers
docker-compose up -d --scale celery-worker=4
```

### Kubernetes (Production)
```bash
# Deploy with automation script
./deploy.sh deploy

# Manual deployment
kubectl apply -f k8s/

# Scale deployments
kubectl scale deployment finops-web --replicas=5 -n finops-dashboard
```

## API Documentation

### Authentication Endpoints
- `POST /auth/login/` - User login with MFA support
- `POST /auth/logout/` - User logout
- `POST /auth/mfa/verify/` - MFA token verification
- `GET /auth/profile/` - User profile information

### AWS Profiles Management
- `GET /api/v1/profiles/` - List AWS profiles
- `POST /api/v1/profiles/` - Create new AWS profile
- `PUT /api/v1/profiles/{id}/` - Update AWS profile
- `DELETE /api/v1/profiles/{id}/` - Delete AWS profile

### Task Management
- `GET /api/v1/tasks/` - List background tasks
- `POST /api/v1/tasks/` - Create new task
- `GET /api/v1/tasks/{id}/` - Get task details
- `POST /api/v1/tasks/{id}/cancel/` - Cancel running task

### Health & Monitoring
- `GET /health/` - Comprehensive health check
- `GET /health/ready/` - Kubernetes readiness probe
- `GET /health/live/` - Kubernetes liveness probe
- `GET /metrics/` - Application metrics

## License

This project is licensed under the MIT License - see the LICENSE file for details.