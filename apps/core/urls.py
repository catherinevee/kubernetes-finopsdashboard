# URL Configuration for Health Check Endpoints
from django.urls import path
from . import health

app_name = 'core'

urlpatterns = [
    path('health/', health.health_check, name='health_check'),
    path('health/ready/', health.readiness_check, name='readiness_check'),
    path('health/live/', health.liveness_check, name='liveness_check'),
    path('metrics/', health.metrics, name='metrics'),
]
