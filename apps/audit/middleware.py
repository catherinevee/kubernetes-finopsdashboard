"""
Audit middleware for comprehensive request tracking and security monitoring.
"""
import logging
import json
import time
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from django.utils import timezone
from apps.authentication.utils import get_client_ip

User = get_user_model()
logger = logging.getLogger('finops_dashboard.audit')


class AuditMiddleware(MiddlewareMixin):
    """
    Comprehensive audit middleware that logs all security-relevant requests.
    
    Features:
    - Request/response logging
    - Security event detection
    - Performance monitoring
    - Anomaly detection
    """
    
    # Sensitive data patterns to redact
    SENSITIVE_PATTERNS = [
        'password', 'secret', 'token', 'key', 'credential',
        'access_key_id', 'secret_access_key', 'session_token'
    ]
    
    # Actions that require audit logging
    AUDITABLE_ACTIONS = [
        'login', 'logout', 'password_change', 'profile_create',
        'profile_update', 'profile_delete', 'command_execute',
        'user_create', 'user_update', 'permission_change'
    ]
    
    # High-risk endpoints
    HIGH_RISK_PATHS = [
        '/api/v1/tasks/',
        '/api/v1/profiles/',
        '/auth/',
        '/admin/',
    ]
    
    def __init__(self, get_response):
        """Initialize middleware."""
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """Process incoming request."""
        # Add request start time for performance monitoring
        request._audit_start_time = time.time()
        
        # Generate unique request ID
        import uuid
        request._audit_request_id = str(uuid.uuid4())
        
        # Extract client information
        request._audit_ip = get_client_ip(request)
        request._audit_user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
        
        # Log high-risk requests
        if any(risk_path in request.path for risk_path in self.HIGH_RISK_PATHS):
            self._log_high_risk_request(request)
    
    def process_response(self, request, response):
        """Process outgoing response."""
        # Calculate request duration
        if hasattr(request, '_audit_start_time'):
            duration = time.time() - request._audit_start_time
            
            # Log slow requests (over 5 seconds)
            if duration > 5.0:
                self._log_slow_request(request, response, duration)
        
        # Log authentication-related responses
        if request.path.startswith('/auth/'):
            self._log_auth_response(request, response)
        
        # Log API responses
        if request.path.startswith('/api/'):
            self._log_api_response(request, response)
        
        # Check for suspicious response patterns
        self._check_suspicious_response(request, response)
        
        return response
    
    def process_exception(self, request, exception):
        """Process unhandled exceptions."""
        self._log_exception(request, exception)
    
    def _log_high_risk_request(self, request):
        """Log high-risk request details."""
        try:
            from .models import AuditLog
            
            # Determine action category
            if request.path.startswith('/auth/'):
                category = 'authentication'
            elif request.path.startswith('/api/'):
                category = 'data_access'
            elif request.path.startswith('/admin/'):
                category = 'user_management'
            else:
                category = 'system'
            
            # Sanitize request data
            sanitized_data = self._sanitize_request_data(request)
            
            AuditLog.objects.create(
                user=request.user if request.user.is_authenticated else None,
                action='high_risk_request',
                action_category=category,
                severity='medium',
                details=f"High-risk request to {request.path}",
                ip_address=request._audit_ip,
                user_agent=request._audit_user_agent,
                session_id=request.session.session_key or '',
                request_id=request._audit_request_id,
                success=True,  # Will be updated in process_response if needed
                additional_data=sanitized_data
            )
            
        except Exception as e:
            logger.error(f"Failed to log high-risk request: {e}")
    
    def _log_auth_response(self, request, response):
        """Log authentication-related responses."""
        try:
            from .models import AuditLog
            
            # Determine if authentication was successful
            success = response.status_code in [200, 302]  # Success or redirect
            
            # Determine specific action
            if 'login' in request.path:
                action = 'login_attempt'
                severity = 'medium' if success else 'high'
            elif 'logout' in request.path:
                action = 'logout'
                severity = 'low'
            elif 'mfa' in request.path:
                action = 'mfa_verification'
                severity = 'medium' if success else 'high'
            else:
                action = 'auth_action'
                severity = 'medium'
            
            # Extract user information
            user = None
            if request.user.is_authenticated:
                user = request.user
            elif hasattr(request, 'POST') and 'email' in request.POST:
                try:
                    user = User.objects.get(email=request.POST['email'])
                except User.DoesNotExist:
                    pass
            
            AuditLog.objects.create(
                user=user,
                action=action,
                action_category='authentication',
                severity=severity,
                details=f"Authentication action on {request.path}: HTTP {response.status_code}",
                ip_address=request._audit_ip,
                user_agent=request._audit_user_agent,
                session_id=request.session.session_key or '',
                request_id=request._audit_request_id,
                success=success,
                additional_data={
                    'response_code': response.status_code,
                    'path': request.path,
                    'method': request.method
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to log auth response: {e}")
    
    def _log_api_response(self, request, response):
        """Log API responses for data access tracking."""
        try:
            from .models import AuditLog
            
            # Only log certain API endpoints
            api_endpoints_to_log = [
                '/api/v1/profiles/',
                '/api/v1/tasks/',
                '/api/v1/dashboard/',
                '/api/v1/audit/'
            ]
            
            if not any(endpoint in request.path for endpoint in api_endpoints_to_log):
                return
            
            success = response.status_code < 400
            
            # Determine action based on HTTP method
            method_actions = {
                'GET': 'data_read',
                'POST': 'data_create',
                'PUT': 'data_update',
                'PATCH': 'data_update',
                'DELETE': 'data_delete'
            }
            
            action = method_actions.get(request.method, 'api_access')
            
            # Determine severity based on response code
            if response.status_code >= 500:
                severity = 'high'
            elif response.status_code >= 400:
                severity = 'medium'
            else:
                severity = 'low'
            
            AuditLog.objects.create(
                user=request.user if request.user.is_authenticated else None,
                action=action,
                action_category='data_access',
                severity=severity,
                details=f"API {request.method} request to {request.path}",
                ip_address=request._audit_ip,
                user_agent=request._audit_user_agent,
                session_id=request.session.session_key or '',
                request_id=request._audit_request_id,
                success=success,
                additional_data={
                    'method': request.method,
                    'path': request.path,
                    'response_code': response.status_code,
                    'content_type': response.get('Content-Type', ''),
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to log API response: {e}")
    
    def _log_slow_request(self, request, response, duration):
        """Log slow requests for performance monitoring."""
        try:
            from .models import AuditLog
            
            AuditLog.objects.create(
                user=request.user if request.user.is_authenticated else None,
                action='slow_request',
                action_category='system',
                severity='medium',
                details=f"Slow request: {request.path} took {duration:.2f} seconds",
                ip_address=request._audit_ip,
                user_agent=request._audit_user_agent,
                session_id=request.session.session_key or '',
                request_id=request._audit_request_id,
                success=True,
                additional_data={
                    'duration_seconds': round(duration, 2),
                    'path': request.path,
                    'method': request.method,
                    'response_code': response.status_code
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to log slow request: {e}")
    
    def _log_exception(self, request, exception):
        """Log unhandled exceptions."""
        try:
            from .models import AuditLog
            
            AuditLog.objects.create(
                user=request.user if request.user.is_authenticated else None,
                action='unhandled_exception',
                action_category='system',
                severity='high',
                details=f"Unhandled exception on {request.path}: {type(exception).__name__}",
                ip_address=getattr(request, '_audit_ip', 'unknown'),
                user_agent=getattr(request, '_audit_user_agent', ''),
                session_id=request.session.session_key or '',
                request_id=getattr(request, '_audit_request_id', ''),
                success=False,
                error_message=str(exception)[:1000],
                additional_data={
                    'exception_type': type(exception).__name__,
                    'path': request.path,
                    'method': request.method
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to log exception: {e}")
    
    def _check_suspicious_response(self, request, response):
        """Check for suspicious response patterns."""
        try:
            # Check for multiple failed authentication attempts
            if (request.path.startswith('/auth/login') and 
                response.status_code in [401, 403]):
                self._check_brute_force_attempt(request)
            
            # Check for unusual response sizes
            if hasattr(response, 'content') and len(response.content) > 10 * 1024 * 1024:  # 10MB
                self._log_large_response(request, response)
            
            # Check for error patterns that might indicate attacks
            if response.status_code == 500:
                self._check_error_pattern(request, response)
                
        except Exception as e:
            logger.error(f"Failed to check suspicious response: {e}")
    
    def _check_brute_force_attempt(self, request):
        """Check for brute force attack patterns."""
        try:
            from .models import AuditLog
            from datetime import timedelta
            
            # Count failed login attempts from same IP in last hour
            recent_failures = AuditLog.objects.filter(
                ip_address=request._audit_ip,
                action='login_attempt',
                success=False,
                timestamp__gte=timezone.now() - timedelta(hours=1)
            ).count()
            
            if recent_failures >= 5:  # Threshold for brute force detection
                self._create_security_incident(
                    'brute_force',
                    f"Brute force attack detected from IP {request._audit_ip}",
                    request._audit_ip,
                    'high'
                )
                
        except Exception as e:
            logger.error(f"Failed to check brute force attempt: {e}")
    
    def _log_large_response(self, request, response):
        """Log unusually large responses."""
        try:
            from .models import AuditLog
            
            content_length = len(response.content)
            
            AuditLog.objects.create(
                user=request.user if request.user.is_authenticated else None,
                action='large_response',
                action_category='system',
                severity='medium',
                details=f"Large response: {content_length} bytes from {request.path}",
                ip_address=request._audit_ip,
                user_agent=request._audit_user_agent,
                session_id=request.session.session_key or '',
                request_id=request._audit_request_id,
                success=True,
                additional_data={
                    'content_length': content_length,
                    'path': request.path,
                    'method': request.method
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to log large response: {e}")
    
    def _check_error_pattern(self, request, response):
        """Check for error patterns that might indicate attacks."""
        try:
            from .models import AuditLog
            from datetime import timedelta
            
            # Count recent 500 errors from same IP
            recent_errors = AuditLog.objects.filter(
                ip_address=request._audit_ip,
                additional_data__response_code=500,
                timestamp__gte=timezone.now() - timedelta(minutes=10)
            ).count()
            
            if recent_errors >= 10:  # Threshold for potential attack
                self._create_security_incident(
                    'suspicious_access',
                    f"Multiple server errors from IP {request._audit_ip}",
                    request._audit_ip,
                    'medium'
                )
                
        except Exception as e:
            logger.error(f"Failed to check error pattern: {e}")
    
    def _create_security_incident(self, incident_type, description, source_ip, severity):
        """Create a security incident."""
        try:
            from .models import SecurityIncident
            
            # Check if similar incident already exists
            existing_incident = SecurityIncident.objects.filter(
                incident_type=incident_type,
                source_ip=source_ip,
                status__in=['open', 'investigating'],
                detected_at__gte=timezone.now() - timezone.timedelta(hours=1)
            ).first()
            
            if existing_incident:
                # Update existing incident
                existing_incident.last_occurrence = timezone.now()
                existing_incident.save(update_fields=['last_occurrence'])
            else:
                # Create new incident
                SecurityIncident.objects.create(
                    incident_type=incident_type,
                    title=f"{incident_type.replace('_', ' ').title()} from {source_ip}",
                    description=description,
                    severity=severity,
                    source_ip=source_ip,
                    first_occurrence=timezone.now(),
                    last_occurrence=timezone.now(),
                    risk_score=self._calculate_incident_risk_score(incident_type, severity)
                )
                
        except Exception as e:
            logger.error(f"Failed to create security incident: {e}")
    
    def _calculate_incident_risk_score(self, incident_type, severity):
        """Calculate risk score for security incident."""
        base_scores = {
            'brute_force': 7,
            'suspicious_access': 5,
            'privilege_escalation': 9,
            'data_exfiltration': 10,
            'command_injection': 8,
            'unauthorized_access': 6,
            'anomalous_behavior': 4
        }
        
        severity_multipliers = {
            'low': 0.5,
            'medium': 1.0,
            'high': 1.5,
            'critical': 2.0
        }
        
        base_score = base_scores.get(incident_type, 5)
        multiplier = severity_multipliers.get(severity, 1.0)
        
        return min(int(base_score * multiplier), 10)
    
    def _sanitize_request_data(self, request):
        """Sanitize request data to remove sensitive information."""
        try:
            data = {}
            
            # Sanitize GET parameters
            if request.GET:
                data['get_params'] = {}
                for key, value in request.GET.items():
                    if any(pattern in key.lower() for pattern in self.SENSITIVE_PATTERNS):
                        data['get_params'][key] = '[REDACTED]'
                    else:
                        data['get_params'][key] = str(value)[:200]  # Limit length
            
            # Sanitize POST data
            if hasattr(request, 'POST') and request.POST:
                data['post_params'] = {}
                for key, value in request.POST.items():
                    if any(pattern in key.lower() for pattern in self.SENSITIVE_PATTERNS):
                        data['post_params'][key] = '[REDACTED]'
                    else:
                        data['post_params'][key] = str(value)[:200]  # Limit length
            
            # Add request metadata
            data['content_type'] = request.content_type
            data['content_length'] = request.META.get('CONTENT_LENGTH', 0)
            
            return data
            
        except Exception as e:
            logger.error(f"Failed to sanitize request data: {e}")
            return {'error': 'Failed to sanitize data'}
