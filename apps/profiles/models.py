"""
AWS Profile models for secure credential and region management.
"""
from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator
from django.utils import timezone
import uuid
import json

User = get_user_model()


class AWSProfile(models.Model):
    """AWS profile configuration with secure credential handling."""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(
        max_length=100,
        validators=[RegexValidator(
            regex=r'^[a-zA-Z0-9_.-]+$',
            message='Profile name can only contain letters, numbers, dots, hyphens, and underscores'
        )]
    )
    description = models.TextField(blank=True)
    
    # AWS Configuration
    account_id = models.CharField(
        max_length=12,
        validators=[RegexValidator(
            regex=r'^\d{12}$',
            message='AWS Account ID must be exactly 12 digits'
        )]
    )
    default_region = models.CharField(
        max_length=20,
        validators=[RegexValidator(
            regex=r'^[a-z]{2,3}-[a-z]+-\d+$',
            message='Invalid AWS region format'
        )]
    )
    regions = models.JSONField(
        default=list,
        help_text='List of AWS regions to include in reports'
    )
    
    # Access Control
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='aws_profiles')
    is_active = models.BooleanField(default=True)
    is_shared = models.BooleanField(default=False)
    allowed_users = models.ManyToManyField(
        User, 
        blank=True, 
        related_name='shared_aws_profiles',
        help_text='Users who can access this shared profile'
    )
    
    # Security & Audit
    role_arn = models.CharField(
        max_length=2048,
        blank=True,
        help_text='IAM role ARN for cross-account access'
    )
    external_id = models.CharField(
        max_length=1224,
        blank=True,
        help_text='External ID for enhanced security'
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ['user', 'name']
        ordering = ['name']
        permissions = [
            ('view_shared_profile', 'Can view shared profiles'),
            ('use_profile', 'Can use profile for reports'),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.account_id})"
    
    def clean(self):
        """Validate profile configuration."""
        from django.core.exceptions import ValidationError
        from apps.authentication.utils import validate_aws_identifier
        
        try:
            validate_aws_identifier(self.name, 'profile')
            validate_aws_identifier(self.default_region, 'region')
            validate_aws_identifier(self.account_id, 'account_id')
        except ValueError as e:
            raise ValidationError(str(e))
        
        # Validate regions list
        if not isinstance(self.regions, list):
            raise ValidationError("Regions must be a list")
        
        for region in self.regions:
            try:
                validate_aws_identifier(region, 'region')
            except ValueError as e:
                raise ValidationError(f"Invalid region '{region}': {e}")
    
    def can_be_used_by(self, user):
        """Check if user has permission to use this profile."""
        if self.user == user:
            return True
        if self.is_shared and user in self.allowed_users.all():
            return True
        return False
    
    def update_last_used(self):
        """Update last used timestamp."""
        self.last_used = timezone.now()
        self.save(update_fields=['last_used'])
    
    def get_regions_display(self):
        """Get formatted regions for display."""
        if not self.regions:
            return self.default_region
        return ', '.join(self.regions)


class ProfileUsageLog(models.Model):
    """Track profile usage for auditing and billing purposes."""
    
    profile = models.ForeignKey(AWSProfile, on_delete=models.CASCADE, related_name='usage_logs')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    command_type = models.CharField(max_length=50)  # 'dashboard', 'audit', 'trend'
    regions_used = models.JSONField(default=list)
    execution_time_seconds = models.IntegerField(null=True, blank=True)
    api_calls_made = models.IntegerField(default=0)
    success = models.BooleanField()
    error_message = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['profile', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
        ]
    
    def __str__(self):
        status = "Success" if self.success else "Failed"
        return f"{self.profile.name} - {self.command_type} - {status} - {self.timestamp}"


class AWSCredential(models.Model):
    """Encrypted AWS credentials with rotation support."""
    
    CREDENTIAL_TYPES = [
        ('iam_role', 'IAM Role (Recommended)'),
        ('access_key', 'Access Key'),
        ('instance_profile', 'EC2 Instance Profile'),
        ('sts_token', 'Temporary STS Token'),
    ]
    
    profile = models.OneToOneField(AWSProfile, on_delete=models.CASCADE, related_name='credentials')
    credential_type = models.CharField(max_length=20, choices=CREDENTIAL_TYPES, default='iam_role')
    
    # Encrypted credential data (using Django's field encryption)
    encrypted_data = models.BinaryField()  # Stores encrypted credential information
    
    # Token management
    expires_at = models.DateTimeField(null=True, blank=True)
    auto_rotate = models.BooleanField(default=True)
    rotation_frequency_hours = models.IntegerField(default=1)  # 1 hour for STS tokens
    
    # Security
    created_at = models.DateTimeField(auto_now_add=True)
    last_rotated = models.DateTimeField(auto_now=True)
    rotation_failures = models.IntegerField(default=0)
    
    class Meta:
        permissions = [
            ('rotate_credentials', 'Can rotate AWS credentials'),
        ]
    
    def __str__(self):
        return f"{self.profile.name} credentials ({self.credential_type})"
    
    def is_expired(self):
        """Check if credentials are expired."""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at
    
    def needs_rotation(self):
        """Check if credentials need rotation."""
        if not self.auto_rotate:
            return False
        
        if self.is_expired():
            return True
        
        if self.credential_type == 'sts_token':
            rotation_threshold = timezone.now() - timezone.timedelta(hours=self.rotation_frequency_hours)
            return self.last_rotated < rotation_threshold
        
        return False


class RegionConfiguration(models.Model):
    """AWS region-specific configuration and status."""
    
    region = models.CharField(
        max_length=20,
        unique=True,
        validators=[RegexValidator(
            regex=r'^[a-z]{2,3}-[a-z]+-\d+$',
            message='Invalid AWS region format'
        )]
    )
    display_name = models.CharField(max_length=100)
    is_enabled = models.BooleanField(default=True)
    
    # Service availability
    supports_cost_explorer = models.BooleanField(default=True)
    supports_budgets = models.BooleanField(default=True)
    supports_ec2 = models.BooleanField(default=True)
    
    # Performance metrics
    avg_response_time_ms = models.IntegerField(null=True, blank=True)
    last_health_check = models.DateTimeField(null=True, blank=True)
    is_healthy = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['region']
    
    def __str__(self):
        return f"{self.region} ({self.display_name})"


class ProfileTemplate(models.Model):
    """Templates for common AWS profile configurations."""
    
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    
    # Template configuration
    default_regions = models.JSONField(default=list)
    recommended_role_policy = models.JSONField(default=dict)
    required_permissions = models.JSONField(default=list)
    
    # Usage
    is_active = models.BooleanField(default=True)
    usage_count = models.IntegerField(default=0)
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name
    
    def increment_usage(self):
        """Increment usage counter."""
        self.usage_count += 1
        self.save(update_fields=['usage_count'])
