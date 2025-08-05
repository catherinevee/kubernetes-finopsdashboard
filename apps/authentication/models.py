"""
Authentication models with role-based access control.
"""
from django.contrib.auth.models import AbstractUser, Permission
from django.db import models
from django.utils import timezone
import uuid


class User(AbstractUser):
    """Extended user model with additional security fields."""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    is_mfa_enabled = models.BooleanField(default=False)
    failed_login_attempts = models.IntegerField(default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    class Meta:
        permissions = [
            ('view_dashboard', 'Can view dashboard'),
            ('run_audit', 'Can run audit reports'),
            ('export_reports', 'Can export reports'),
            ('manage_profiles', 'Can manage AWS profiles'),
        ]
    
    def is_account_locked(self):
        """Check if account is currently locked."""
        if self.account_locked_until:
            return timezone.now() < self.account_locked_until
        return False
    
    def lock_account(self, duration_minutes=30):
        """Lock account for specified duration."""
        self.account_locked_until = timezone.now() + timezone.timedelta(minutes=duration_minutes)
        self.save(update_fields=['account_locked_until'])
    
    def unlock_account(self):
        """Unlock account and reset failed attempts."""
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=['account_locked_until', 'failed_login_attempts'])


class Role(models.Model):
    """Role model for RBAC implementation."""
    
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField()
    permissions = models.ManyToManyField(Permission)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name


class UserRole(models.Model):
    """User role assignment with optional resource-level permissions."""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='role_assignments')
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    resource_type = models.CharField(max_length=50, blank=True)  # e.g., 'profile'
    resource_id = models.CharField(max_length=100, blank=True)   # e.g., 'prod-account'
    granted_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='granted_roles')
    granted_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'role', 'resource_type', 'resource_id']
    
    def __str__(self):
        if self.resource_type and self.resource_id:
            return f"{self.user.username} - {self.role.name} on {self.resource_type}:{self.resource_id}"
        return f"{self.user.username} - {self.role.name}"


class LoginAttempt(models.Model):
    """Track login attempts for security monitoring."""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    email = models.EmailField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    success = models.BooleanField()
    failure_reason = models.CharField(max_length=100, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        status = "Success" if self.success else f"Failed ({self.failure_reason})"
        return f"{self.email} - {status} - {self.timestamp}"


class MFADevice(models.Model):
    """Track MFA device registration and usage."""
    
    DEVICE_TYPES = [
        ('totp', 'TOTP (Authenticator App)'),
        ('sms', 'SMS'),
        ('email', 'Email'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mfa_devices')
    device_type = models.CharField(max_length=10, choices=DEVICE_TYPES)
    device_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    backup_tokens = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ['user', 'device_name']
    
    def __str__(self):
        return f"{self.user.username} - {self.device_name} ({self.device_type})"
