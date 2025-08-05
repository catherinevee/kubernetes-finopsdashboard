# Health Check Views for FinOps Dashboard
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.db import connections
from django.core.cache import cache
import redis
from celery import current_app
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)

@never_cache
@csrf_exempt
@require_http_methods(["GET"])
def health_check(request):
    """
    Comprehensive health check endpoint for Kubernetes probes
    """
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'checks': {},
        'version': '1.0.0'
    }
    
    overall_status = True
    
    # Database connectivity check
    try:
        db_conn = connections['default']
        with db_conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        health_status['checks']['database'] = {
            'status': 'healthy',
            'message': 'Database connection successful'
        }
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        health_status['checks']['database'] = {
            'status': 'unhealthy',
            'message': f'Database connection failed: {str(e)}'
        }
        overall_status = False
    
    # Redis connectivity check
    try:
        cache.set('health_check', 'test', 10)
        test_value = cache.get('health_check')
        if test_value == 'test':
            health_status['checks']['redis'] = {
                'status': 'healthy',
                'message': 'Redis connection successful'
            }
        else:
            raise Exception("Redis test value mismatch")
    except Exception as e:
        logger.error(f"Redis health check failed: {str(e)}")
        health_status['checks']['redis'] = {
            'status': 'unhealthy',
            'message': f'Redis connection failed: {str(e)}'
        }
        overall_status = False
    
    # Celery broker check
    try:
        inspect = current_app.control.inspect()
        stats = inspect.stats()
        if stats:
            health_status['checks']['celery'] = {
                'status': 'healthy',
                'message': f'Celery workers: {len(stats)} active'
            }
        else:
            health_status['checks']['celery'] = {
                'status': 'degraded',
                'message': 'No Celery workers responding'
            }
    except Exception as e:
        logger.error(f"Celery health check failed: {str(e)}")
        health_status['checks']['celery'] = {
            'status': 'unhealthy',
            'message': f'Celery connection failed: {str(e)}'
        }
        overall_status = False
    
    # Set overall status
    if not overall_status:
        health_status['status'] = 'unhealthy'
        return JsonResponse(health_status, status=503)
    
    # Check for degraded services
    degraded_services = [
        service for service, details in health_status['checks'].items()
        if details['status'] == 'degraded'
    ]
    
    if degraded_services:
        health_status['status'] = 'degraded'
        return JsonResponse(health_status, status=200)
    
    return JsonResponse(health_status, status=200)

@never_cache
@csrf_exempt
@require_http_methods(["GET"])
def readiness_check(request):
    """
    Kubernetes readiness probe endpoint
    """
    try:
        # Check if application is ready to serve requests
        db_conn = connections['default']
        with db_conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        
        return JsonResponse({
            'status': 'ready',
            'timestamp': datetime.now().isoformat()
        }, status=200)
    except Exception as e:
        logger.error(f"Readiness check failed: {str(e)}")
        return JsonResponse({
            'status': 'not_ready',
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }, status=503)

@never_cache
@csrf_exempt
@require_http_methods(["GET"])
def liveness_check(request):
    """
    Kubernetes liveness probe endpoint
    """
    return JsonResponse({
        'status': 'alive',
        'timestamp': datetime.now().isoformat()
    }, status=200)

@never_cache
@csrf_exempt
@require_http_methods(["GET"])
def metrics(request):
    """
    Basic metrics endpoint for monitoring
    """
    try:
        from django.contrib.auth import get_user_model
        from apps.tasks.models import Task
        from apps.audit.models import AuditLog
        
        User = get_user_model()
        
        metrics_data = {
            'timestamp': datetime.now().isoformat(),
            'users': {
                'total': User.objects.count(),
                'active': User.objects.filter(is_active=True).count(),
            },
            'tasks': {
                'total': Task.objects.count(),
                'running': Task.objects.filter(status='RUNNING').count(),
                'completed': Task.objects.filter(status='SUCCESS').count(),
                'failed': Task.objects.filter(status='FAILURE').count(),
            },
            'audit_logs': {
                'total': AuditLog.objects.count(),
                'today': AuditLog.objects.filter(
                    timestamp__date=datetime.now().date()
                ).count(),
            }
        }
        
        return JsonResponse(metrics_data, status=200)
    except Exception as e:
        logger.error(f"Metrics collection failed: {str(e)}")
        return JsonResponse({
            'error': 'Metrics collection failed',
            'timestamp': datetime.now().isoformat()
        }, status=500)
