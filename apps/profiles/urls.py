# Profiles URL Configuration
from django.urls import path
from . import views

app_name = 'profiles'

urlpatterns = [
    path('', views.profile_list, name='list'),
    path('create/', views.profile_create, name='create'),
    path('<int:pk>/', views.profile_detail, name='detail'),
    path('<int:pk>/edit/', views.profile_edit, name='edit'),
    path('<int:pk>/delete/', views.profile_delete, name='delete'),
    path('<int:pk>/test-connection/', views.test_connection, name='test_connection'),
]
