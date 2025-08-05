"""
Celery tasks for secure background execution of FinOps CLI commands.
"""
import os
import logging
from typing import Dict, Any
from datetime import datetime, timedelta
from celery import shared_task, current_task
from django.utils import timezone
from django.conf import settings

from apps.core.cli_wrapper import cli_wrapper
from apps.profiles.aws_utils import AWSCredentialManager
from .models import FinOpsTask, TaskQueue, TaskMetrics

logger = logging.getLogger('finops_dashboard.tasks')


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def execute_finops_command(self, task_uuid: str, command_type: str, params: Dict, user_id: str):
    """
    Execute FinOps CLI command as background task with comprehensive error handling.
    
    Args:
        task_uuid: UUID of the FinOpsTask instance
        command_type: Type of command ('dashboard', 'audit', 'trend')
        params: Command parameters
        user_id: User ID for audit logging
        
    Returns:
        Dict: Task execution result
    """
    task_instance = None
    
    try:
        # Get task instance
        task_instance = FinOpsTask.objects.get(id=task_uuid)
        
        # Update Celery task ID
        task_instance.task_id = self.request.id
        task_instance.mark_started()
        
        logger.info(f"Starting FinOps task {task_uuid}: {command_type}")
        
        # Step 1: Validate profile and credentials (10% progress)
        task_instance.update_progress(10, "Validating AWS credentials")
        
        profile = task_instance.profile_used
        credential_manager = AWSCredentialManager()
        
        # Test credentials
        cred_test = credential_manager.test_credentials(profile)
        if not cred_test['success']:
            raise ValueError(f"AWS credential validation failed: {cred_test['error']}")
        
        # Step 2: Prepare CLI execution (20% progress)
        task_instance.update_progress(20, "Preparing CLI command")
        
        # Validate and sanitize parameters
        try:
            validated_params = cli_wrapper.validate_command_params(command_type, params)
        except ValueError as e:
            raise ValueError(f"Parameter validation failed: {e}")
        
        # Step 3: Set up AWS environment (30% progress)
        task_instance.update_progress(30, "Setting up AWS environment")
        
        # Create temporary credentials for CLI
        temp_credentials = credential_manager.create_sts_session(
            profile, 
            duration_seconds=settings.FINOPS_CLI_TIMEOUT + 300  # Add buffer
        )
        
        # Set environment variables for CLI
        env_vars = {
            'AWS_ACCESS_KEY_ID': temp_credentials['access_key_id'],
            'AWS_SECRET_ACCESS_KEY': temp_credentials['secret_access_key'],
            'AWS_DEFAULT_REGION': profile.default_region
        }
        
        if 'session_token' in temp_credentials:
            env_vars['AWS_SESSION_TOKEN'] = temp_credentials['session_token']
        
        # Temporarily set environment variables
        original_env = {}
        for key, value in env_vars.items():
            original_env[key] = os.environ.get(key)
            os.environ[key] = value
        
        try:
            # Step 4: Execute CLI command (40-90% progress)
            task_instance.update_progress(40, f"Executing {command_type} command")
            
            # Execute the command
            result = cli_wrapper.execute_command(command_type, validated_params)
            
            if not result['success']:
                raise ValueError(f"CLI execution failed: {result.get('error', 'Unknown error')}")
            
            # Step 5: Process results (90% progress)
            task_instance.update_progress(90, "Processing results")
            
            # Save result data
            result_data = {
                'execution_time': result.get('execution_metadata', {}).get('execution_time', 0),
                'output_size': result.get('execution_metadata', {}).get('output_size', 0),
                'command_output': result.get('stdout', '')[:5000],  # Limit stored output
            }
            
            # If there's a parsed output, include it
            if 'parsed_output' in result:
                result_data['parsed_output'] = result['parsed_output']
            
            # Step 6: Finalize task (100% progress)
            task_instance.update_progress(100, "Task completed successfully")
            task_instance.mark_completed(result_data=result_data)
            
            # Update profile usage
            profile.update_last_used()
            
            # Log successful execution
            logger.info(f"FinOps task {task_uuid} completed successfully")
            
            # Update metrics
            _update_task_metrics(task_instance, success=True)
            
            return {
                'success': True,
                'task_id': task_uuid,
                'result_data': result_data,
                'execution_time': task_instance.get_duration()
            }
            
        finally:
            # Restore original environment variables
            for key, original_value in original_env.items():
                if original_value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = original_value
    
    except Exception as e:
        error_message = str(e)
        logger.error(f"FinOps task {task_uuid} failed: {error_message}")
        
        if task_instance:
            # Handle retry logic
            if self.request.retries < self.max_retries:
                task_instance.retry_count += 1
                task_instance.save(update_fields=['retry_count'])
                
                logger.info(f"Retrying task {task_uuid} (attempt {self.request.retries + 1})")
                
                # Exponential backoff
                countdown = 60 * (2 ** self.request.retries)
                raise self.retry(countdown=countdown, exc=e)
            else:
                # Mark as failed after all retries exhausted
                task_instance.mark_failed(error_message)
                _update_task_metrics(task_instance, success=False)
        
        return {
            'success': False,
            'task_id': task_uuid,
            'error': error_message,
            'retries': self.request.retries
        }


@shared_task
def cleanup_expired_tasks():
    """Clean up expired tasks and associated files."""
    try:
        cutoff_time = timezone.now()
        
        # Find expired tasks
        expired_tasks = FinOpsTask.objects.filter(
            expires_at__lt=cutoff_time,
            status__in=['completed', 'failed', 'cancelled']
        )
        
        cleanup_count = 0
        for task in expired_tasks:
            try:
                # Clean up result files
                if task.result_file:
                    result_path = os.path.join(settings.MEDIA_ROOT, task.result_file)
                    if os.path.exists(result_path):
                        os.remove(result_path)
                
                # Delete task record
                task.delete()
                cleanup_count += 1
                
            except Exception as e:
                logger.error(f"Failed to cleanup task {task.id}: {e}")
        
        if cleanup_count > 0:
            logger.info(f"Cleaned up {cleanup_count} expired tasks")
        
        # Also cleanup temporary CLI files
        cli_wrapper.cleanup_temp_files(max_age_hours=2)
        
        return {
            'success': True,
            'tasks_cleaned': cleanup_count
        }
        
    except Exception as e:
        logger.error(f"Task cleanup failed: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@shared_task
def rotate_aws_credentials():
    """Rotate AWS credentials that need rotation."""
    try:
        from apps.profiles.models import AWSCredential
        
        credentials_needing_rotation = AWSCredential.objects.filter(
            auto_rotate=True
        )
        
        rotation_count = 0
        for credential in credentials_needing_rotation:
            if credential.needs_rotation():
                try:
                    credential_manager = AWSCredentialManager()
                    success = credential_manager.rotate_credentials(credential.profile)
                    
                    if success:
                        rotation_count += 1
                        logger.info(f"Rotated credentials for profile {credential.profile.name}")
                    else:
                        logger.warning(f"Failed to rotate credentials for profile {credential.profile.name}")
                
                except Exception as e:
                    logger.error(f"Credential rotation error for {credential.profile.name}: {e}")
        
        return {
            'success': True,
            'rotations_performed': rotation_count
        }
        
    except Exception as e:
        logger.error(f"Credential rotation task failed: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@shared_task
def generate_task_metrics():
    """Generate hourly task metrics for analytics."""
    try:
        current_time = timezone.now()
        current_date = current_time.date()
        current_hour = current_time.hour
        
        # Get tasks from the current hour
        hour_start = current_time.replace(minute=0, second=0, microsecond=0)
        hour_end = hour_start + timedelta(hours=1)
        
        tasks_in_hour = FinOpsTask.objects.filter(
            created_at__gte=hour_start,
            created_at__lt=hour_end
        )
        
        # Calculate metrics
        total_tasks = tasks_in_hour.count()
        completed_tasks = tasks_in_hour.filter(status='completed').count()
        failed_tasks = tasks_in_hour.filter(status='failed').count()
        cancelled_tasks = tasks_in_hour.filter(status='cancelled').count()
        
        # Performance metrics
        completed_task_durations = []
        total_cpu_time = 0
        total_memory_usage = 0
        total_api_calls = 0
        
        for task in tasks_in_hour:
            duration = task.get_duration()
            if duration:
                completed_task_durations.append(duration)
            
            if task.cpu_time_seconds:
                total_cpu_time += task.cpu_time_seconds
            
            if task.memory_usage_mb:
                total_memory_usage += task.memory_usage_mb
            
            total_api_calls += task.api_calls_made
        
        avg_execution_time = (
            sum(completed_task_durations) / len(completed_task_durations)
            if completed_task_durations else None
        )
        
        # Count by command type
        dashboard_tasks = tasks_in_hour.filter(command_type='dashboard').count()
        audit_tasks = tasks_in_hour.filter(command_type='audit').count()
        trend_tasks = tasks_in_hour.filter(command_type='trend').count()
        
        # Create or update metrics record
        metrics, created = TaskMetrics.objects.get_or_create(
            date=current_date,
            hour=current_hour,
            defaults={
                'total_tasks': total_tasks,
                'completed_tasks': completed_tasks,
                'failed_tasks': failed_tasks,
                'cancelled_tasks': cancelled_tasks,
                'avg_execution_time_seconds': avg_execution_time,
                'total_cpu_time_seconds': total_cpu_time,
                'total_memory_usage_mb': total_memory_usage,
                'total_api_calls': total_api_calls,
                'dashboard_tasks': dashboard_tasks,
                'audit_tasks': audit_tasks,
                'trend_tasks': trend_tasks,
            }
        )
        
        if not created:
            # Update existing record
            metrics.total_tasks = total_tasks
            metrics.completed_tasks = completed_tasks
            metrics.failed_tasks = failed_tasks
            metrics.cancelled_tasks = cancelled_tasks
            metrics.avg_execution_time_seconds = avg_execution_time
            metrics.total_cpu_time_seconds = total_cpu_time
            metrics.total_memory_usage_mb = total_memory_usage
            metrics.total_api_calls = total_api_calls
            metrics.dashboard_tasks = dashboard_tasks
            metrics.audit_tasks = audit_tasks
            metrics.trend_tasks = trend_tasks
            metrics.save()
        
        logger.info(f"Generated task metrics for {current_date} {current_hour}:00")
        
        return {
            'success': True,
            'date': str(current_date),
            'hour': current_hour,
            'total_tasks': total_tasks
        }
        
    except Exception as e:
        logger.error(f"Metrics generation failed: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@shared_task
def send_task_notifications(task_uuid: str):
    """Send notifications for completed tasks."""
    try:
        task_instance = FinOpsTask.objects.get(id=task_uuid)
        
        # Get pending notifications
        notifications = task_instance.notifications.filter(sent=False)
        
        sent_count = 0
        for notification in notifications:
            try:
                if notification.notification_type == 'email':
                    success = _send_email_notification(notification, task_instance)
                elif notification.notification_type == 'webhook':
                    success = _send_webhook_notification(notification, task_instance)
                else:
                    success = False
                
                if success:
                    notification.sent = True
                    notification.sent_at = timezone.now()
                    sent_count += 1
                else:
                    notification.delivery_attempts += 1
                
                notification.save()
                
            except Exception as e:
                notification.delivery_attempts += 1
                notification.last_error = str(e)
                notification.save()
                logger.error(f"Notification delivery failed: {e}")
        
        return {
            'success': True,
            'notifications_sent': sent_count
        }
        
    except FinOpsTask.DoesNotExist:
        logger.error(f"Task not found for notifications: {task_uuid}")
        return {
            'success': False,
            'error': 'Task not found'
        }
    except Exception as e:
        logger.error(f"Notification task failed: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def _update_task_metrics(task_instance, success: bool):
    """Update task metrics after execution."""
    try:
        # Update resource usage if available
        if hasattr(task_instance, 'memory_usage_mb') and not task_instance.memory_usage_mb:
            # Could implement resource monitoring here
            pass
        
        # Update API calls made
        if task_instance.result_data and 'api_calls' in task_instance.result_data:
            task_instance.api_calls_made = task_instance.result_data['api_calls']
            task_instance.save(update_fields=['api_calls_made'])
        
        # Log metrics for monitoring
        logger.info(f"Task metrics updated for {task_instance.id}: success={success}")
        
    except Exception as e:
        logger.error(f"Failed to update task metrics: {e}")


def _send_email_notification(notification, task_instance):
    """Send email notification for task completion."""
    try:
        from django.core.mail import send_mail
        
        subject = f"FinOps Task Completed: {task_instance.command_type}"
        
        if task_instance.status == 'completed':
            message = f"Your {task_instance.command_type} task has completed successfully."
        else:
            message = f"Your {task_instance.command_type} task failed: {task_instance.error_message}"
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[notification.recipient],
            fail_silently=False
        )
        
        return True
        
    except Exception as e:
        logger.error(f"Email notification failed: {e}")
        return False


def _send_webhook_notification(notification, task_instance):
    """Send webhook notification for task completion."""
    try:
        import requests
        
        payload = {
            'task_id': str(task_instance.id),
            'command_type': task_instance.command_type,
            'status': task_instance.status,  
            'completed_at': task_instance.completed_at.isoformat() if task_instance.completed_at else None,
            'duration_seconds': task_instance.get_duration(),
        }
        
        if task_instance.status == 'failed':
            payload['error'] = task_instance.error_message
        
        response = requests.post(
            notification.recipient,
            json=payload,
            timeout=30,
            headers={'Content-Type': 'application/json'}
        )
        
        response.raise_for_status()
        return True
        
    except Exception as e:
        logger.error(f"Webhook notification failed: {e}")
        return False
