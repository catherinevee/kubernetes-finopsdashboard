"""
Audit models for comprehensive security logging and compliance tracking.
"""
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid
import json

User = get_user_model()


class AuditLog(models.Model):
    """Comprehensive audit logging for all security-relevant actions."""
    
    ACTION_CATEGORIES = [
        ('authentication', 'Authentication'),
        ('authorization', 'Authorization'),
        ('data_access', 'Data Access'),
        ('configuration', 'Configuration Change'),
        ('command_execution', 'Command Execution'),
        ('profile_management', 'Profile Management'),
        ('user_management', 'User Management'),
        ('system', 'System Event'),
    ]
    
    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    # Primary identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Event details
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=100)
    action_category = models.CharField(max_length=20, choices=ACTION_CATEGORIES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='medium')
    
    # Command execution details (if applicable)
    command_executed = models.TextField(blank=True)
    command_type = models.CharField(max_length=50, blank=True)
    command_params = models.JSONField(null=True, blank=True)
    
    # Context and details
    details = models.TextField()
    resource_type = models.CharField(max_length=100, blank=True)
    resource_id = models.CharField(max_length=255, blank=True)
    
    # Request context
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    session_id = models.CharField(max_length=255, blank=True)
    request_id = models.CharField(max_length=255, blank=True)
    
    # Results
    success = models.BooleanField()
    error_message = models.TextField(blank=True)
    
    # Metadata
    additional_data = models.JSONField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Compliance and retention
    retention_period_days = models.IntegerField(default=2555)  # 7 years default
    is_sensitive = models.BooleanField(default=False)
    compliance_tags = models.JSONField(default=list, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action_category', 'timestamp']),
            models.Index(fields=['severity', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['success', 'timestamp']),
        ]
    
    def __str__(self):
        user_display = self.user.email if self.user else 'Anonymous'
        return f"{user_display} - {self.action} - {self.timestamp}"
    
    def is_expired(self):
        """Check if audit log has passed retention period."""
        expiry_date = self.timestamp + timezone.timedelta(days=self.retention_period_days)
        return timezone.now() > expiry_date
    
    def get_risk_score(self):
        """Calculate risk score based on various factors."""
        score = 0
        
        # Base score by severity
        severity_scores = {'low': 1, 'medium': 3, 'high': 7, 'critical': 10}
        score += severity_scores.get(self.severity, 3)
        
        # Failed actions are riskier
        if not self.success:
            score += 2
        
        # Certain action categories are riskier
        risky_categories = ['authentication', 'authorization', 'command_execution']
        if self.action_category in risky_categories:
            score += 1
        
        # Multiple failures from same IP increase risk
        recent_failures = AuditLog.objects.filter(
            ip_address=self.ip_address,
            success=False,
            timestamp__gte=timezone.now() - timezone.timedelta(hours=1)
        ).count()
        
        if recent_failures > 3:
            score += 3
        
        return min(score, 10)  # Cap at 10


class SecurityIncident(models.Model):
    """Security incidents detected through audit log analysis."""
    
    INCIDENT_TYPES = [
        ('brute_force', 'Brute Force Attack'),
        ('suspicious_access', 'Suspicious Access Pattern'),
        ('privilege_escalation', 'Privilege Escalation Attempt'),
        ('data_exfiltration', 'Potential Data Exfiltration'),
        ('command_injection', 'Command Injection Attempt'),
        ('unauthorized_access', 'Unauthorized Access'),
        ('anomalous_behavior', 'Anomalous User Behavior'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('investigating', 'Under Investigation'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    # Identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    incident_type = models.CharField(max_length=30, choices=INCIDENT_TYPES)
    title = models.CharField(max_length=200)
    description = models.TextField()
    
    # Status and severity
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    severity = models.CharField(max_length=10, choices=AuditLog.SEVERITY_LEVELS)
    risk_score = models.IntegerField()
    
    # Associated data
    affected_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    source_ip = models.GenericIPAddressField()
    related_logs = models.ManyToManyField(AuditLog, blank=True)
    
    # Investigation
    assigned_to = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='assigned_incidents'
    )
    investigation_notes = models.TextField(blank=True)
    
    # Timing
    detected_at = models.DateTimeField(auto_now_add=True)
    first_occurrence = models.DateTimeField()
    last_occurrence = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # Actions taken
    actions_taken = models.JSONField(default=list, blank=True)
    auto_mitigated = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['status', 'severity']),
            models.Index(fields=['incident_type', 'detected_at']),
            models.Index(fields=['affected_user', 'detected_at']),
        ]
    
    def __str__(self):
        return f"{self.incident_type} - {self.title} ({self.status})"
    
    def add_action_taken(self, action_description, taken_by):
        """Add an action taken during incident response."""
        action = {
            'timestamp': timezone.now().isoformat(),
            'action': action_description,
            'taken_by': taken_by.email if taken_by else 'System',
        }
        
        if not self.actions_taken:
            self.actions_taken = []
        
        self.actions_taken.append(action)
        self.save(update_fields=['actions_taken'])
    
    def resolve(self, resolution_notes, resolved_by):
        """Mark incident as resolved."""
        self.status = 'resolved'
        self.resolved_at = timezone.now()
        self.investigation_notes += f"\n\nResolved by {resolved_by.email}: {resolution_notes}"
        self.save(update_fields=['status', 'resolved_at', 'investigation_notes'])


class ComplianceReport(models.Model):
    """Compliance reporting for various standards and regulations."""
    
    COMPLIANCE_STANDARDS = [
        ('soc2', 'SOC 2'),
        ('iso27001', 'ISO 27001'),
        ('pci_dss', 'PCI DSS'),
        ('hipaa', 'HIPAA'),
        ('gdpr', 'GDPR'),
        ('custom', 'Custom Standard'),
    ]
    
    REPORT_PERIODS = [
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('annual', 'Annual'),
    ]
    
    # Report identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    compliance_standard = models.CharField(max_length=20, choices=COMPLIANCE_STANDARDS)
    report_period = models.CharField(max_length=20, choices=REPORT_PERIODS)
    
    # Report timeframe
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    
    # Report data
    total_events = models.IntegerField(default=0)
    compliant_events = models.IntegerField(default=0)
    non_compliant_events = models.IntegerField(default=0)
    security_incidents = models.IntegerField(default=0)
    
    # Detailed findings
    findings = models.JSONField(default=dict)
    recommendations = models.JSONField(default=list)
    
    # Report metadata
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    generated_at = models.DateTimeField(auto_now_add=True)
    report_file = models.CharField(max_length=255, blank=True)
    
    # Status
    is_final = models.BooleanField(default=False)
    approved_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='approved_compliance_reports'
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-generated_at']
        unique_together = ['compliance_standard', 'report_period', 'period_start']
    
    def __str__(self):
        return f"{self.compliance_standard} - {self.report_period} - {self.period_start.date()}"
    
    def calculate_compliance_percentage(self):
        """Calculate overall compliance percentage."""
        if self.total_events == 0:
            return 100.0
        return (self.compliant_events / self.total_events) * 100
    
    def approve(self, approved_by):
        """Approve the compliance report."""
        self.is_final = True
        self.approved_by = approved_by
        self.approved_at = timezone.now()
        self.save(update_fields=['is_final', 'approved_by', 'approved_at'])


class AlertRule(models.Model):
    """Rules for generating alerts based on audit log patterns."""
    
    RULE_TYPES = [
        ('threshold', 'Threshold Based'),
        ('pattern', 'Pattern Matching'),
        ('anomaly', 'Anomaly Detection'),
        ('time_based', 'Time Based'),
    ]
    
    # Rule definition
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField()
    rule_type = models.CharField(max_length=20, choices=RULE_TYPES)
    
    # Rule parameters
    conditions = models.JSONField(help_text="JSON configuration for rule conditions")
    threshold = models.IntegerField(null=True, blank=True)
    time_window_minutes = models.IntegerField(default=60)
    
    # Actions
    alert_severity = models.CharField(max_length=10, choices=AuditLog.SEVERITY_LEVELS)
    create_incident = models.BooleanField(default=False)
    send_notification = models.BooleanField(default=True)
    notification_recipients = models.JSONField(default=list)
    
    # Rule status
    is_active = models.BooleanField(default=True)
    last_triggered = models.DateTimeField(null=True, blank=True)
    trigger_count = models.IntegerField(default=0)
    
    # Metadata
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} ({self.rule_type})"
    
    def trigger(self, matching_logs):
        """Trigger the alert rule."""
        self.last_triggered = timezone.now()
        self.trigger_count += 1
        self.save(update_fields=['last_triggered', 'trigger_count'])
        
        # Create alert
        alert = Alert.objects.create(
            rule=self,
            severity=self.alert_severity,
            title=f"Alert: {self.name}",
            description=f"Rule '{self.name}' was triggered",
            triggered_by_logs=matching_logs,
        )
        
        return alert


class Alert(models.Model):
    """Alerts generated by alert rules."""
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('acknowledged', 'Acknowledged'),
        ('resolved', 'Resolved'),
        ('suppressed', 'Suppressed'),
    ]
    
    # Alert identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    rule = models.ForeignKey(AlertRule, on_delete=models.CASCADE, related_name='alerts')
    
    # Alert details
    title = models.CharField(max_length=200)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=AuditLog.SEVERITY_LEVELS)
    
    # Status and handling
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    acknowledged_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='acknowledged_alerts'
    )
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    
    # Associated data
    triggered_by_logs = models.ManyToManyField(AuditLog, blank=True)
    related_incident = models.ForeignKey(
        SecurityIncident, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True
    )
    
    # Timing
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # Notification tracking
    notifications_sent = models.JSONField(default=list)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'severity']),
            models.Index(fields=['rule', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.severity} ({self.status})"
    
    def acknowledge(self, acknowledged_by):
        """Acknowledge the alert."""
        self.status = 'acknowledged'
        self.acknowledged_by = acknowledged_by
        self.acknowledged_at = timezone.now()
        self.save(update_fields=['status', 'acknowledged_by', 'acknowledged_at'])
    
    def resolve(self, resolved_by):
        """Resolve the alert."""
        self.status = 'resolved'
        self.resolved_at = timezone.now()
        self.save(update_fields=['status', 'resolved_at'])


class DataRetentionPolicy(models.Model):
    """Data retention policies for audit logs and compliance."""
    
    # Policy definition
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField()
    
    # Retention rules
    default_retention_days = models.IntegerField()
    sensitive_data_retention_days = models.IntegerField()
    
    # Category-specific retention
    category_retention = models.JSONField(
        default=dict,
        help_text="Retention periods by audit log category"
    )
    
    # Compliance requirements
    compliance_standards = models.JSONField(default=list)
    legal_hold_override = models.BooleanField(default=False)
    
    # Policy status
    is_active = models.BooleanField(default=True)
    effective_date = models.DateTimeField()
    
    # Metadata
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-effective_date']
        verbose_name_plural = "Data retention policies"
    
    def __str__(self):
        return self.name
    
    def get_retention_period(self, audit_log):
        """Get retention period for a specific audit log."""
        if audit_log.is_sensitive:
            return self.sensitive_data_retention_days
        
        category_retention = self.category_retention.get(audit_log.action_category)
        if category_retention:
            return category_retention
        
        return self.default_retention_days
