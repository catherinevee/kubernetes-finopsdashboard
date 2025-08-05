# Dashboard URL Configuration
from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.dashboard_home, name='home'),
    path('aws-cost-overview/', views.aws_cost_overview, name='aws_cost_overview'),
    path('resource-utilization/', views.resource_utilization, name='resource_utilization'),
    path('recommendations/', views.recommendations, name='recommendations'),
    path('reports/', views.reports, name='reports'),
]
