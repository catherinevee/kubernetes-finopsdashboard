# Audit URL Configuration
from django.urls import path
from . import views

app_name = 'audit'

urlpatterns = [
    path('', views.audit_log_list, name='log_list'),
    path('security-incidents/', views.security_incidents, name='security_incidents'),
    path('user-activity/', views.user_activity, name='user_activity'),
    path('compliance-report/', views.compliance_report, name='compliance_report'),
    path('export/', views.export_logs, name='export_logs'),
]
