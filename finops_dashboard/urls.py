# FinOps Dashboard URL Configuration
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),
    
    # Health checks and metrics (no auth required)
    path('', include('apps.core.urls')),
    
    # OAuth2 endpoints
    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    
    # Authentication endpoints
    path('auth/', include('apps.authentication.urls')),
    
    # Main application areas
    path('dashboard/', include('apps.dashboard.urls')),
    path('profiles/', include('apps.profiles.urls')),
    path('tasks/', include('apps.tasks.urls')),
    path('audit/', include('apps.audit.urls')),
    
    # API endpoints
    path('api/v1/', include('apps.api.urls')),
    
    # Root redirect to dashboard
    path('', RedirectView.as_view(url='/dashboard/', permanent=False)),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Custom error handlers
handler404 = 'apps.core.views.handler404'
handler500 = 'apps.core.views.handler500'
handler403 = 'apps.core.views.handler403'
