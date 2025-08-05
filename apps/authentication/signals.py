"""
Authentication signals for automatic user setup and security monitoring.
"""
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.utils import timezone
import logging

from .models import User, LoginAttempt
from .utils import get_client_ip, create_audit_log

logger = logging.getLogger('finops_dashboard.auth')


@receiver(post_save, sender=User)
def user_post_save(sender, instance, created, **kwargs):
    """Handle user creation and updates."""
    if created:
        logger.info(f"New user created: {instance.email}")
        # Additional setup can be added here (e.g., default roles, welcome email)


@receiver(user_logged_in)
def user_logged_in_handler(sender, request, user, **kwargs):
    """Handle successful user login."""
    ip_address = get_client_ip(request)
    
    # Reset failed login attempts
    if user.failed_login_attempts > 0:
        user.failed_login_attempts = 0
        user.last_failed_login = None
        user.save(update_fields=['failed_login_attempts', 'last_failed_login'])
    
    # Update last login
    user.last_login = timezone.now()
    user.save(update_fields=['last_login'])
    
    logger.info(f"User logged in: {user.email} from {ip_address}")


@receiver(user_logged_out)
def user_logged_out_handler(sender, request, user, **kwargs):
    """Handle user logout."""
    if user:
        ip_address = get_client_ip(request)
        logger.info(f"User logged out: {user.email} from {ip_address}")


@receiver(user_login_failed)
def user_login_failed_handler(sender, credentials, request, **kwargs):
    """Handle failed login attempts."""
    email = credentials.get('username', 'unknown')
    ip_address = get_client_ip(request)
    
    logger.warning(f"Failed login attempt: {email} from {ip_address}")
    
    # Try to find user and increment failed attempts
    try:
        user = User.objects.get(email=email)
        user.failed_login_attempts += 1
        user.last_failed_login = timezone.now()
        
        # Lock account after 5 failed attempts
        if user.failed_login_attempts >= 5:
            user.lock_account(30)  # 30 minutes
            logger.warning(f"Account locked due to failed attempts: {email}")
        
        user.save()
    except User.DoesNotExist:
        pass  # User doesn't exist, but don't reveal this information
