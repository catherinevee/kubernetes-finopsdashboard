# FinOps Dashboard Web Interface

## Purpose and Overview

The FinOps Dashboard is a secure Django web application that provides enterprise teams with web-based access to AWS financial operations and cost management capabilities. This application eliminates the need for direct command-line access while maintaining comprehensive audit trails for compliance requirements.

### What This Application Does

The primary purpose of this application is to democratize AWS cost management across enterprise teams by providing a secure, web-based interface to AWS FinOps CLI tools. The application enables:

**Cost Visibility**: Real-time AWS spending monitoring across multiple accounts and regions with interactive dashboards and detailed cost breakdowns.

**Resource Optimization**: Automated identification of idle resources, rightsizing recommendations for EC2 and RDS instances, and Reserved Instance optimization analysis.

**Financial Governance**: Role-based access control ensuring appropriate team members can view relevant cost data while maintaining security boundaries and audit compliance.

**Operational Efficiency**: Background processing of long-running cost analysis tasks with progress tracking and automated report generation.

### How It Works

The application operates as a secure wrapper around AWS FinOps CLI commands, processing requests through multiple layers:

1. **Authentication Layer**: Users authenticate via OAuth2/JWT with mandatory multi-factor authentication (MFA) using TOTP or SMS verification.

2. **Authorization Layer**: Role-based access control determines which AWS profiles and cost data each user can access based on their organizational permissions.

3. **Request Processing**: User requests for cost analysis or resource optimization are validated and queued for background processing using Celery task queues.

4. **Secure CLI Execution**: Background workers execute AWS CLI commands in isolated environments with encrypted credential management and comprehensive input validation to prevent injection attacks.

5. **Data Presentation**: Results are processed, cached, and presented through responsive Bootstrap 5 interfaces with interactive charts and exportable reports.

6. **Audit and Compliance**: All user actions, CLI executions, and data access are logged with tamper-evident audit trails for compliance and security monitoring.

### Core Technology Stack

Built on Django 4.2+ with PostgreSQL for data persistence, Redis for caching and task queues, and Celery for background processing. The interface uses Bootstrap 5 for cross-browser compatibility in enterprise environments. Deployment supports both Docker Compose for development and Kubernetes for production scaling.

### Key Benefits for Teams

**Finance Teams**: Access AWS cost data without requiring AWS console permissions, generate automated monthly reports with team-based cost allocation, and set up budget monitoring with variance tracking.

**Engineering Teams**: Review resource utilization and performance metrics, receive rightsizing recommendations, and identify optimization opportunities without direct AWS access.

**Management**: Monitor high-level cost KPIs and trends, track FinOps initiative ROI, and make data-driven cloud investment decisions through executive dashboards.

## Core Functionality

### Primary Purpose
Provides web access to AWS FinOps CLI functionality for teams that need:

- Cost visualization across multiple AWS accounts and regions
- Resource utilization monitoring and rightsizing recommendations  
- Automated report generation with scheduled delivery
- Secure CLI command execution with full audit logging
- Role-based access for finance, engineering, and management teams

### Core Functionality

#### Cost Management
Real-time spending monitoring with budget alerts and variance tracking. Handles cost allocation by teams and projects, with automated tagging for untagged resources. Includes Reserved Instance optimization and Savings Plan analysis.

#### Resource Optimization  
Identifies idle resources and provides rightsizing recommendations for EC2 and RDS instances. Compares costs across regions and analyzes performance versus cost trade-offs.

#### Financial Operations
Approval workflows for high-cost operations. Chargeback reporting with cost center allocation. Executive dashboards with KPI tracking for FinOps initiatives.

#### Integration Capabilities
API endpoints for existing financial systems. Scheduled report distribution via email. Cost analysis integration with CI/CD pipelines for infrastructure changes.

## System Architecture

### Application Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                     Web Interface Layer                        │
├─────────────────────────────────────────────────────────────────┤
│  Frontend: Bootstrap 5 + Chart.js                              │
│  - Cost dashboards and resource views                          │
│  - Report generator with export options                        │
│  - User management and audit interface                         │
├─────────────────────────────────────────────────────────────────┤
│  API Layer: Django REST Framework                              │
│  - Authentication and user management                          │
│  - FinOps data processing and aggregation                      │
│  - Task management and audit logging                           │
├─────────────────────────────────────────────────────────────────┤
│  Business Logic: Django Applications                           │
│  - apps/dashboard: Cost analysis and reporting                 │
│  - apps/profiles: AWS credential management                    │
│  - apps/tasks: Background job processing                       │
│  - apps/audit: Security and compliance logging                 │
│  - apps/authentication: OAuth2/MFA implementation              │
├─────────────────────────────────────────────────────────────────┤
│  Background Processing: Celery + Redis                         │
│  - CLI command execution in isolated workers                   │
│  - Report generation and data collection                       │
│  - Scheduled tasks and cleanup operations                      │
├─────────────────────────────────────────────────────────────────┤
│  Security Layer                                                │
│  - OAuth2/JWT authentication with MFA                          │
│  - Role-based authorization (RBAC)                             │
│  - Command injection prevention                                │
│  - Encrypted AWS credential storage                            │
├─────────────────────────────────────────────────────────────────┤
│  Data Layer                                                     │
│  - PostgreSQL: User data, audit logs, configurations           │
│  - Redis: Session cache, task queue, API response cache        │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AWS FinOps CLI                            │
│  - Cost & Billing API integration                              │
│  - CloudWatch metrics collection                               │
│  - Resource inventory and recommendations                      │
│  - Reserved Instance and Savings Plan analysis                 │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         AWS Services                           │
│  Multi-account, multi-region cost and resource data            │
└─────────────────────────────────────────────────────────────────┘
```

### Request Processing Flow

```
User Request → Authentication → Authorization → API Layer
     │                                              │
     │                                              ▼
     └─ Web Interface ← Response ← Business Logic ──┘
                                        │
                                        ▼
                                   Task Queue → Background Worker
                                        │              │
                                        │              ▼
                                        │       CLI Wrapper → AWS CLI
                                        │              │
                                        │              ▼
                                        │       Result Processing
                                        │              │
                                        ▼              ▼
                                   Database ← Audit Log
```

## Key Features

### Security Implementation
- OAuth2/JWT authentication with django-oauth-toolkit
- Mandatory multi-factor authentication using django-otp
- Role-based access control with custom permissions
- Account lockout after failed login attempts
- Complete audit logging with security incident detection
- Command injection prevention (never uses shell=True)
- Input validation using Pydantic models
- Security headers and Content Security Policy
- Rate limiting for authentication and API endpoints

### Technology Stack
- Django 4.2+ with PostgreSQL database
- Celery with Redis for background task processing
- Bootstrap 5 responsive interface
- RESTful API with Django REST Framework
- Docker containerization with security best practices
- Kubernetes deployment manifests
- Nginx reverse proxy with SSL termination

### AWS Integration
- Secure wrapper around AWS FinOps CLI commands
- Encrypted AWS credential storage per user profile
- Background processing for long-running CLI operations
- Real-time progress tracking for active tasks
- Complete command history with audit trail
- Resource usage monitoring and cost analysis

### Operations Support
- Health check endpoints for Kubernetes probes
- Structured logging for centralized log management
- Metrics collection for monitoring and alerting
- Automated backup configurations
- Performance monitoring with resource usage tracking

## Getting Started

### Prerequisites
- Docker and Docker Compose
- Kubernetes cluster (production deployment)
- Python 3.11+ (local development)
- PostgreSQL 15+
- Redis 7+

### Local Development Setup

1. **Environment setup:**
```bash
git clone <repository-url>
cd kubernetes-finopsdashboard
cp .env.template .env
# Configure .env with your specific values
```

2. **Start services:**
```bash
docker-compose up -d
```

3. **Initialize application:**
```bash
# Database migrations
docker-compose exec web python manage.py migrate

# Create admin user
docker-compose exec web python manage.py createsuperuser

# Collect static files
docker-compose exec web python manage.py collectstatic --noinput
```

4. **Access points:**
- Main interface: http://localhost:8000
- Admin panel: http://localhost:8000/admin
- Health check: http://localhost:8000/health/

### Production Deployment

1. **Build and publish images:**
```bash
export DOCKER_REGISTRY=your-registry.com
export VERSION=1.0.0
./deploy.sh push
```

2. **Configure secrets:**
```bash
# Generate base64 encoded secrets for k8s/00-namespace-config.yaml
echo -n "your-secret-key" | base64
```

3. **Deploy to cluster:**
```bash
./deploy.sh deploy
```

4. **Verify deployment:**
```bash
./deploy.sh info
./deploy.sh health
```

## Project Structure

### Directory Layout

```
finops_dashboard/
├── apps/authentication/          # User Authentication & MFA
│   ├── models.py                 # User, Role, LoginAttempt, MFADevice
│   ├── views.py                  # Login, logout, MFA verification
│   ├── serializers.py            # API data serialization
│   └── urls.py                   # Authentication routes
├── apps/profiles/                # AWS Profile Management
│   ├── models.py                 # AWSProfile with encrypted credentials
│   ├── views.py                  # CRUD operations for AWS profiles
│   ├── forms.py                  # Profile creation and edit forms
│   └── encryption.py             # Credential encryption utilities
├── apps/tasks/                   # Background Task Processing
│   ├── models.py                 # Task, TaskResult, TaskMetrics
│   ├── tasks.py                  # Celery task definitions
│   ├── views.py                  # Task monitoring interface
│   └── utils.py                  # Task queue management
├── apps/audit/                   # Security & Compliance Logging
│   ├── models.py                 # AuditLog, SecurityIncident, ComplianceReport
│   ├── middleware.py             # Request/response audit middleware
│   ├── views.py                  # Audit trail interface
│   └── signals.py                # Automated audit triggers
├── apps/dashboard/               # Main FinOps Dashboard
│   ├── models.py                 # Dashboard configurations, saved reports
│   ├── views.py                  # Cost dashboards, resource views
│   ├── charts.py                 # Chart.js data preparation
│   └── reports.py                # Report generation logic
├── apps/core/                    # Core Utilities & Security
│   ├── cli_wrapper.py            # Secure AWS CLI command execution
│   ├── health.py                 # Kubernetes health checks
│   ├── validators.py             # Input validation functions
│   └── encryption.py             # Data encryption utilities
├── apps/api/                     # RESTful API Layer
│   ├── serializers.py            # API data serialization
│   ├── viewsets.py               # DRF viewsets for all resources
│   ├── permissions.py            # API access control
│   └── urls.py                   # API endpoint routing
├── templates/                    # Bootstrap 5 HTML Templates
│   ├── base.html                 # Main layout with navigation
│   ├── auth/                     # Login, MFA, registration forms
│   ├── dashboard/                # Cost dashboards, charts, reports
│   ├── profiles/                 # AWS profile management interface
│   └── tasks/                    # Task monitoring and history
├── static/                       # Frontend Assets
│   ├── css/                      # Custom CSS styles
│   ├── js/                       # JavaScript for interactivity
│   └── img/                      # Images and icons
├── k8s/                          # Kubernetes Deployment
│   ├── 00-namespace-config.yaml  # Namespace, ConfigMap, Secrets
│   ├── 01-postgres.yaml          # PostgreSQL database
│   ├── 02-redis.yaml             # Redis cache and broker
│   ├── 03-web-app.yaml           # Django web application
│   ├── 04-celery.yaml            # Celery workers and beat scheduler
│   └── 05-ingress-networking.yaml # Ingress, services, network policies
├── nginx/                        # Reverse Proxy Configuration
│   ├── nginx.conf                # Main nginx configuration
│   └── conf.d/default.conf       # Application-specific config
├── requirements.txt              # Python dependencies
├── docker-compose.yml            # Local development environment
├── Dockerfile                    # Web application container
├── Dockerfile.celery             # Celery worker container
├── deploy.sh                     # Deployment automation script
└── .env.template                 # Environment configuration template
```

### Database Schema

```sql
-- User Management & Authentication
Users (id, username, email, is_active, last_login, failed_attempts, locked_until)
Roles (id, name, description, permissions)
UserRoles (user_id, role_id, assigned_date)
LoginAttempts (id, user_id, ip_address, success, timestamp)
MFADevices (id, user_id, device_type, secret_key, is_active)

-- AWS Profile Management
AWSProfiles (id, user_id, name, description, aws_access_key_id_encrypted, 
             aws_secret_access_key_encrypted, region, created_date, last_used)

-- Background Task Processing
Tasks (id, user_id, profile_id, command, status, created_date, started_date, 
       completed_date, result, error_message, progress_percentage)
TaskResults (id, task_id, output_data, metrics, file_paths)
TaskMetrics (id, task_id, cpu_usage, memory_usage, execution_time)

-- Security & Audit Logging
AuditLogs (id, user_id, action, resource_type, resource_id, ip_address, 
           user_agent, timestamp, details, risk_level)
SecurityIncidents (id, incident_type, severity, description, detected_date, 
                   resolved_date, status, affected_users)
ComplianceReports (id, report_type, generated_date, period_start, period_end, 
                   findings, recommendations, status)

-- Dashboard & Reporting
DashboardConfigs (id, user_id, name, config_json, is_default, created_date)
SavedReports (id, user_id, name, report_type, parameters, schedule, 
              last_generated, next_run)
```

### User Workflows

```
Authentication Flow:
User Login → MFA Challenge → Token Generation → Session Creation
     │              │               │                  │
     └─ Audit Log   └─ Device Verify └─ JWT/OAuth2     └─ RBAC Setup

Cost Analysis Flow:
Dashboard Request → Profile Selection → CLI Command Queue → Background Processing
         │                 │                  │                     │
         └─ User Context   └─ Credential Decrypt └─ Secure Execution └─ Result Cache
```

## User Scenarios

### Finance Teams
Access cost data across AWS accounts without requiring AWS console access. Generate monthly reports with cost breakdowns by team and project. Set up budget alerts and monitor spending variance against forecasts.

Key workflows:
- Dashboard overview with real-time spending data
- Cost analysis with drill-down capabilities  
- Budget monitoring and alert configuration
- Chargeback report generation for different teams

### Engineering Teams  
Review resource utilization without direct AWS access. Get rightsizing recommendations and identify idle resources. Monitor performance impact of cost optimization changes.

Key workflows:
- Resource dashboard with utilization metrics
- Rightsizing recommendations for EC2/RDS instances
- Idle resource identification and cleanup suggestions
- Cost-aware development integration

### Management and Executives
High-level cost KPIs and trends without technical AWS details. Track FinOps initiative ROI and make data-driven cloud investment decisions.

Key workflows:
- Executive dashboard with summary metrics
- KPI tracking and trend analysis  
- Strategic planning with cost projections
- ROI analysis for cloud investments

## Security Implementation

### Authentication Architecture
Four-layer security model addresses different attack vectors:

**Network Security**: TLS/SSL encryption, Kubernetes network policies, firewall rules, VPN access requirements.

**Application Security**: OAuth2/JWT authentication, mandatory MFA (TOTP/SMS), role-based access control, session timeout management, account lockout protection.

**Data Security**: AES-256 encrypted credential storage, database encryption at rest, secure key management, PII data protection, audit trail integrity.

**Command Security**: Parameter arrays prevent shell injection (never uses shell=True), input validation with whitelisting, command pattern restrictions, resource usage limits, execution sandboxing.

### Performance and Scalability
Horizontal scaling design supports enterprise load:

**Web Application**: 3+ replicas with load balancing, auto-scaling based on CPU/memory usage.

**Background Workers**: Celery workers scale based on queue depth, separate queues for different task types.

**Data Layer**: PostgreSQL read replicas for reporting queries, Redis cluster mode for high availability.

**Caching Strategy**: Multi-level caching with Redis for sessions/tasks, Django cache for query results, CDN for static assets.

### Monitoring and Operations

**Application Metrics**: User activity tracking, task processing statistics, security event monitoring, performance metrics collection, business KPI tracking.

**Health Endpoints**:
- `GET /health/` - Database, Redis, and Celery connectivity check
- `GET /health/ready/` - Kubernetes readiness probe  
- `GET /health/live/` - Kubernetes liveness probe
- `GET /metrics/` - Prometheus-compatible application metrics

**Logging Strategy**: Structured JSON logging with multiple destinations - application logs for debugging, security logs for compliance, performance logs for monitoring, error logs for alerting.

## Security Requirements

### Command Execution Safety
The CLI wrapper prevents command injection attacks that are common in applications that shell out to external commands. Never uses `shell=True` in subprocess calls. Input validation uses whitelists rather than blacklists. All CLI parameters are passed as arrays to prevent interpretation of shell metacharacters.

### Data Protection  
AWS credentials are encrypted using Django's built-in encryption before database storage. PII data has field-level encryption. Audit trails maintain integrity through cryptographic hashing. Database connections use SSL/TLS encryption.

### Authentication and Authorization
OAuth2/JWT implementation with configurable token expiration. Multi-factor authentication is mandatory for all users (TOTP or SMS). Role-based permissions follow least-privilege principle. Account lockout triggers after configurable failed attempts. Session management uses secure cookies with appropriate flags.

### Infrastructure Security
Container images run as non-root users with read-only root filesystems where possible. Kubernetes security contexts drop all capabilities except those explicitly required. Network policies restrict pod-to-pod communication to necessary services only. All external communications require TLS/SSL encryption.

## Configuration Reference

### Required Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Django cryptographic signing key | None (required) |
| `DATABASE_URL` | PostgreSQL connection string | None (required) |
| `CELERY_BROKER_URL` | Redis connection for task queue | None (required) |
| `OAUTH2_CLIENT_SECRET` | OAuth2 application secret | None (required) |

### Security Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `DEBUG` | Enable debug mode (never in production) | `False` |
| `MFA_REQUIRED` | Enforce MFA for all user accounts | `True` |
| `SESSION_TIMEOUT` | Session timeout in seconds | `3600` |
| `RATE_LIMIT_LOGIN` | Login attempts per minute | `5/m` |
| `RATE_LIMIT_API` | API requests per hour per user | `100/h` |

## Deployment Methods

### Development Environment
```bash
# Local development with auto-reload
docker-compose up

# Scale background workers
docker-compose up --scale celery-worker=4

# View aggregated logs
docker-compose logs -f web celery-worker
```

### Production Environment  
```bash
# Full deployment with health checks
./deploy.sh deploy

# Manual Kubernetes deployment
kubectl apply -f k8s/

# Scale specific components
kubectl scale deployment finops-web --replicas=5 -n finops-dashboard
kubectl scale deployment celery-worker --replicas=10 -n finops-dashboard
```

## API Reference

### Authentication Endpoints
- `POST /auth/login/` - User login with optional MFA challenge
- `POST /auth/logout/` - Invalidate current session
- `POST /auth/mfa/verify/` - Submit MFA token for verification
- `GET /auth/profile/` - Current user profile and permissions

### AWS Profile Management
- `GET /api/v1/profiles/` - List user's AWS profiles
- `POST /api/v1/profiles/` - Create new AWS profile with encrypted credentials
- `PUT /api/v1/profiles/{id}/` - Update existing AWS profile
- `DELETE /api/v1/profiles/{id}/` - Remove AWS profile
- `POST /api/v1/profiles/{id}/test/` - Test AWS credentials connectivity

### Background Task Management
- `GET /api/v1/tasks/` - List user's background tasks
- `POST /api/v1/tasks/` - Queue new CLI command for background execution
- `GET /api/v1/tasks/{id}/` - Get task status and results
- `POST /api/v1/tasks/{id}/cancel/` - Cancel running task
- `GET /api/v1/tasks/{id}/logs/` - Get task execution logs

### System Health and Monitoring
- `GET /health/` - Complete system health check (database, cache, workers)
- `GET /health/ready/` - Kubernetes readiness probe endpoint
- `GET /health/live/` - Kubernetes liveness probe endpoint  
- `GET /metrics/` - Application metrics in Prometheus format

## License

This project is licensed under the MIT License.