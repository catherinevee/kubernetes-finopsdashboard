"""
Authentication utility functions for security operations.
"""
import re
import logging
import ipaddress
from typing import Optional
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone

logger = logging.getLogger('finops_dashboard.auth')


def get_client_ip(request) -> str:
    """
    Extract client IP address from request, handling proxies and load balancers.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Take the first IP in the chain (original client)
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', 'unknown')
    
    # Validate IP address format
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        logger.warning(f"Invalid IP address detected: {ip}")
        return 'unknown'


def validate_password_strength(password: str) -> str:
    """
    Validate password strength beyond Django's default validation.
    """
    # Django's built-in validation
    try:
        validate_password(password)
    except ValidationError as e:
        raise ValueError('; '.join(e.messages))
    
    # Additional custom validation
    if len(password) < 12:
        raise ValueError('Password must be at least 12 characters long')
    
    if not re.search(r'[A-Z]', password):
        raise ValueError('Password must contain at least one uppercase letter')
    
    if not re.search(r'[a-z]', password):
        raise ValueError('Password must contain at least one lowercase letter')
    
    if not re.search(r'\d', password):
        raise ValueError('Password must contain at least one digit')
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValueError('Password must contain at least one special character')
    
    # Check for common patterns
    if re.search(r'(.)\1{3,}', password):  # 4+ repeated characters
        raise ValueError('Password cannot contain 4 or more repeated characters')
    
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', password.lower()):
        raise ValueError('Password cannot contain sequential characters')
    
    return password


def create_audit_log(user, action: str, details: str, ip_address: str):
    """
    Create an audit log entry for security-relevant actions.
    """
    from apps.audit.models import AuditLog
    
    try:
        AuditLog.objects.create(
            user=user,
            action=action,
            command_executed='',  # Not applicable for auth actions
            details=details,
            ip_address=ip_address,
            timestamp=timezone.now()
        )
        logger.info(f"Audit log created: {user.email} - {action} - {details}")
    except Exception as e:
        logger.error(f"Failed to create audit log: {e}")


def validate_aws_identifier(identifier: str, identifier_type: str = 'general') -> str:
    """
    Validate AWS resource identifiers to prevent injection attacks.
    """
    if not identifier:
        raise ValueError(f"AWS {identifier_type} identifier cannot be empty")
    
    # Common AWS identifier pattern (letters, numbers, hyphens, underscores, dots)
    if not re.match(r'^[a-zA-Z0-9_.-]+$', identifier):
        raise ValueError(f"Invalid AWS {identifier_type} identifier format")
    
    # Length validation
    if len(identifier) > 128:
        raise ValueError(f"AWS {identifier_type} identifier too long (max 128 characters)")
    
    # Specific validations by type
    if identifier_type == 'region':
        # AWS region format: us-east-1, eu-west-2, etc.
        if not re.match(r'^[a-z]{2,3}-[a-z]+-\d+$', identifier):
            raise ValueError("Invalid AWS region format")
    
    elif identifier_type == 'profile':
        # AWS profile names
        if len(identifier) > 64:
            raise ValueError("AWS profile name too long (max 64 characters)")
        if identifier.startswith('-') or identifier.endswith('-'):
            raise ValueError("AWS profile name cannot start or end with hyphen")
    
    elif identifier_type == 'account_id':
        # AWS account ID is 12 digits
        if not re.match(r'^\d{12}$', identifier):
            raise ValueError("AWS account ID must be exactly 12 digits")
    
    return identifier


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent directory traversal and other attacks.
    """
    if not filename:
        raise ValueError("Filename cannot be empty")
    
    # Remove directory traversal patterns
    filename = filename.replace('..', '').replace('/', '').replace('\\', '')
    
    # Allow only safe characters
    filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
    
    # Ensure reasonable length
    if len(filename) > 255:
        filename = filename[:255]
    
    # Ensure it doesn't start with dot (hidden file)
    if filename.startswith('.'):
        filename = 'file_' + filename[1:]
    
    return filename


def validate_json_structure(data: dict, required_fields: list, max_depth: int = 5) -> bool:
    """
    Validate JSON structure to prevent complex object attacks.
    """
    def check_depth(obj, current_depth=0):
        if current_depth > max_depth:
            raise ValueError(f"JSON structure too deep (max {max_depth} levels)")
        
        if isinstance(obj, dict):
            for value in obj.values():
                check_depth(value, current_depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                check_depth(item, current_depth + 1)
    
    try:
        check_depth(data)
        
        # Verify required fields
        for field in required_fields:
            if field not in data:
                raise ValueError(f"Required field '{field}' missing")
        
        return True
    except Exception as e:
        logger.warning(f"JSON validation failed: {e}")
        return False


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    """
    import secrets
    return secrets.token_urlsafe(length)


def rate_limit_key_generator(group, request):
    """
    Generate rate limiting keys based on user and IP.
    """
    if request.user.is_authenticated:
        return f"{group}:user:{request.user.id}"
    else:
        return f"{group}:ip:{get_client_ip(request)}"
