"""
Task models for background job management and tracking.
"""
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.validators import RegexValidator
import uuid
import json

User = get_user_model()


class FinOpsTask(models.Model):
    """Background task for FinOps CLI operations."""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
        ('timeout', 'Timeout'),
    ]
    
    COMMAND_TYPES = [
        ('dashboard', 'Dashboard Generation'),
        ('audit', 'Audit Report'),
        ('trend', 'Trend Analysis'),
    ]
    
    # Primary identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    task_id = models.CharField(max_length=255, unique=True)  # Celery task ID
    
    # Task configuration
    command_type = models.CharField(max_length=20, choices=COMMAND_TYPES)
    command_params = models.JSONField(default=dict)
    profile_used = models.ForeignKey(
        'profiles.AWSProfile', 
        on_delete=models.CASCADE, 
        related_name='tasks'
    )
    
    # Execution tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    progress_percentage = models.IntegerField(default=0)
    current_step = models.CharField(max_length=200, blank=True)
    
    # Results and output
    result_file = models.CharField(max_length=255, blank=True)
    result_data = models.JSONField(null=True, blank=True)
    output_format = models.CharField(max_length=20, default='json')
    file_size_bytes = models.BigIntegerField(null=True, blank=True)
    
    # Error handling
    error_message = models.TextField(blank=True)
    error_code = models.CharField(max_length=50, blank=True)
    retry_count = models.IntegerField(default=0)
    max_retries = models.IntegerField(default=3)
    
    # Timing
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    
    # User and audit
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='finops_tasks')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    
    # Resource usage
    memory_usage_mb = models.IntegerField(null=True, blank=True)
    cpu_time_seconds = models.FloatField(null=True, blank=True)
    api_calls_made = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"{self.command_type} - {self.status} - {self.created_at}"
    
    def save(self, *args, **kwargs):
        """Override save to set expiration time."""
        if not self.expires_at:
            # Tasks expire 24 hours after creation
            self.expires_at = timezone.now() + timezone.timedelta(hours=24)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        """Check if task has expired."""
        return timezone.now() > self.expires_at
    
    def can_be_cancelled(self):
        """Check if task can be cancelled."""
        return self.status in ['pending', 'running']
    
    def can_be_retried(self):
        """Check if task can be retried."""
        return (
            self.status in ['failed', 'timeout'] and 
            self.retry_count < self.max_retries
        )
    
    def get_duration(self):
        """Get task duration if completed."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        elif self.started_at:
            return (timezone.now() - self.started_at).total_seconds()
        return None
    
    def get_progress_display(self):
        """Get formatted progress display."""
        if self.status == 'completed':
            return "100%"
        elif self.status == 'failed':
            return "Failed"
        elif self.status == 'cancelled':
            return "Cancelled"
        else:
            return f"{self.progress_percentage}%"
    
    def update_progress(self, percentage, step_description=""):
        """Update task progress."""
        self.progress_percentage = min(100, max(0, percentage))
        self.current_step = step_description[:200]
        self.save(update_fields=['progress_percentage', 'current_step'])
    
    def mark_started(self):
        """Mark task as started."""
        self.status = 'running'
        self.started_at = timezone.now()
        self.save(update_fields=['status', 'started_at'])
    
    def mark_completed(self, result_file=None, result_data=None):
        """Mark task as completed."""
        self.status = 'completed'
        self.completed_at = timezone.now()
        self.progress_percentage = 100
        
        if result_file:
            self.result_file = result_file
        if result_data:
            self.result_data = result_data
        
        self.save(update_fields=[
            'status', 'completed_at', 'progress_percentage', 
            'result_file', 'result_data'
        ])
    
    def mark_failed(self, error_message, error_code=""):
        """Mark task as failed."""
        self.status = 'failed'
        self.completed_at = timezone.now()
        self.error_message = error_message[:5000]  # Limit error message length
        self.error_code = error_code[:50]
        
        self.save(update_fields=[
            'status', 'completed_at', 'error_message', 'error_code'
        ])


class TaskQueue(models.Model):
    """Task queue management for controlling concurrent executions."""
    
    name = models.CharField(max_length=100, unique=True)
    max_concurrent_tasks = models.IntegerField(default=5)
    current_running_tasks = models.IntegerField(default=0)
    priority = models.IntegerField(default=100)  # Lower number = higher priority
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['priority', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.current_running_tasks}/{self.max_concurrent_tasks})"
    
    def can_accept_task(self):
        """Check if queue can accept a new task."""
        return (
            self.is_active and 
            self.current_running_tasks < self.max_concurrent_tasks
        )
    
    def increment_running_tasks(self):
        """Increment running task counter."""
        self.current_running_tasks += 1
        self.save(update_fields=['current_running_tasks'])
    
    def decrement_running_tasks(self):
        """Decrement running task counter."""
        self.current_running_tasks = max(0, self.current_running_tasks - 1)
        self.save(update_fields=['current_running_tasks'])


class TaskNotification(models.Model):
    """Task completion notifications."""
    
    NOTIFICATION_TYPES = [
        ('email', 'Email'),
        ('webhook', 'Webhook'),
        ('browser', 'Browser Notification'),
    ]
    
    task = models.ForeignKey(FinOpsTask, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    recipient = models.CharField(max_length=255)  # email or webhook URL
    
    # Delivery tracking
    sent = models.BooleanField(default=False)
    sent_at = models.DateTimeField(null=True, blank=True)
    delivery_attempts = models.IntegerField(default=0)
    last_error = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['task', 'notification_type', 'recipient']
    
    def __str__(self):
        return f"{self.task.id} - {self.notification_type} - {self.recipient}"


class TaskSchedule(models.Model):
    """Scheduled task execution."""
    
    FREQUENCY_CHOICES = [
        ('once', 'Run Once'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
    ]
    
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    
    # Task configuration
    command_type = models.CharField(max_length=20, choices=FinOpsTask.COMMAND_TYPES)
    command_params = models.JSONField(default=dict)
    profile = models.ForeignKey('profiles.AWSProfile', on_delete=models.CASCADE)
    
    # Schedule configuration
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)
    scheduled_time = models.TimeField()
    timezone = models.CharField(max_length=50, default='UTC')
    
    # Status
    is_active = models.BooleanField(default=True)
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField()
    
    # User and audit
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['next_run']
    
    def __str__(self):
        return f"{self.name} - {self.frequency}"
    
    def calculate_next_run(self):
        """Calculate next execution time."""
        from datetime import timedelta
        
        if self.frequency == 'once':
            return None
        elif self.frequency == 'daily':
            return self.last_run + timedelta(days=1) if self.last_run else timezone.now()
        elif self.frequency == 'weekly':
            return self.last_run + timedelta(weeks=1) if self.last_run else timezone.now()
        elif self.frequency == 'monthly':
            # Approximate monthly scheduling
            return self.last_run + timedelta(days=30) if self.last_run else timezone.now()
        
        return timezone.now()
    
    def update_next_run(self):
        """Update next run time after execution."""
        self.last_run = timezone.now()
        self.next_run = self.calculate_next_run()
        
        if self.frequency == 'once':
            self.is_active = False
        
        self.save(update_fields=['last_run', 'next_run', 'is_active'])


class TaskMetrics(models.Model):
    """Task execution metrics and analytics."""
    
    # Time period
    date = models.DateField()
    hour = models.IntegerField()  # 0-23
    
    # Metrics
    total_tasks = models.IntegerField(default=0)
    completed_tasks = models.IntegerField(default=0)
    failed_tasks = models.IntegerField(default=0)
    cancelled_tasks = models.IntegerField(default=0)
    
    # Performance metrics
    avg_execution_time_seconds = models.FloatField(null=True, blank=True)
    total_cpu_time_seconds = models.FloatField(default=0)
    total_memory_usage_mb = models.BigIntegerField(default=0)
    total_api_calls = models.IntegerField(default=0)
    
    # By command type
    dashboard_tasks = models.IntegerField(default=0)
    audit_tasks = models.IntegerField(default=0)
    trend_tasks = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['date', 'hour']
        ordering = ['-date', '-hour']
    
    def __str__(self):
        return f"Metrics for {self.date} {self.hour}:00 - {self.total_tasks} tasks"
