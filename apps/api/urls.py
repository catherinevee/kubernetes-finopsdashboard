# API URL Configuration
from django.urls import path, include

app_name = 'api'

urlpatterns = [
    path('auth/', include('apps.authentication.api_urls')),
    path('dashboard/', include('apps.dashboard.api_urls')),
    path('profiles/', include('apps.profiles.api_urls')),
    path('tasks/', include('apps.tasks.api_urls')),
    path('audit/', include('apps.audit.api_urls')),
]
