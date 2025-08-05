"""
Authentication views with rate limiting and account lockout.
"""
import logging
from datetime import timedelta
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from django.core.exceptions import ValidationError
from django_otp import user_has_device
from django_otp.decorators import otp_required
from django_ratelimit.decorators import ratelimit
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from oauth2_provider.models import Application, AccessToken
from pydantic import BaseModel, EmailStr, Field, validator
import re

from .models import User, LoginAttempt, MFADevice
from .forms import LoginForm, RegisterForm, MFASetupForm
from .utils import get_client_ip, create_audit_log, validate_password_strength

logger = logging.getLogger('finops_dashboard.auth')

# Pydantic models for API validation
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    remember_me: bool = False
    
    @validator('email')
    def validate_email_format(cls, v):
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
            raise ValueError('Invalid email format')
        return v.lower()

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=30)
    password: str = Field(..., min_length=12)
    confirm_password: str
    first_name: str = Field(..., max_length=30)
    last_name: str = Field(..., max_length=30)
    
    @validator('username')
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_.-]+$', v):
            raise ValueError('Username can only contain letters, numbers, dots, hyphens, and underscores')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        return validate_password_strength(v)
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class MFAVerifyRequest(BaseModel):
    token: str = Field(..., min_length=6, max_length=6)
    
    @validator('token')
    def validate_token(cls, v):
        if not v.isdigit():
            raise ValueError('Token must be numeric')
        return v


@never_cache
@csrf_protect
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@require_http_methods(["GET", "POST"])
def login_view(request):
    """Handle user login with rate limiting and failed attempt tracking."""
    if request.user.is_authenticated:
        return redirect('dashboard:home')
    
    if request.method == 'POST':
        try:
            # Validate input using Pydantic
            login_data = LoginRequest(**request.POST.dict())
            
            # Get client information
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
            
            # Check for existing user
            try:
                user = User.objects.get(email=login_data.email)
            except User.DoesNotExist:
                user = None
            
            # Record login attempt
            login_attempt = LoginAttempt.objects.create(
                user=user,
                email=login_data.email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False
            )
            
            # Check if account is locked
            if user and user.is_account_locked():
                login_attempt.failure_reason = 'Account locked'
                login_attempt.save()
                logger.warning(f"Login attempt on locked account: {login_data.email} from {ip_address}")
                messages.error(request, 'Account is temporarily locked. Please try again later.')
                return render(request, 'auth/login.html')
            
            # Authenticate user
            user = authenticate(request, username=login_data.email, password=login_data.password)
            
            if user is not None:
                if user.is_active:
                    # Check if MFA is required
                    if user.is_mfa_enabled and user_has_device(user):
                        # Store user ID in session for MFA verification
                        request.session['pre_2fa_user_id'] = str(user.id)
                        request.session['pre_2fa_ip'] = ip_address
                        
                        login_attempt.success = True
                        login_attempt.failure_reason = 'Pending MFA'
                        login_attempt.save()
                        
                        logger.info(f"User {user.email} passed first factor authentication from {ip_address}")
                        return redirect('auth:mfa_verify')
                    else:
                        # Complete login
                        login(request, user)
                        user.unlock_account()  # Reset any failed attempts
                        
                        login_attempt.success = True
                        login_attempt.save()
                        
                        # Set session expiry
                        if not login_data.remember_me:
                            request.session.set_expiry(0)  # Browser close
                        
                        logger.info(f"User {user.email} logged in successfully from {ip_address}")
                        create_audit_log(user, 'login', f"Login from {ip_address}", ip_address)
                        
                        next_url = request.GET.get('next', 'dashboard:home')
                        return redirect(next_url)
                else:
                    login_attempt.failure_reason = 'Account disabled'
                    login_attempt.save()
                    logger.warning(f"Login attempt on disabled account: {login_data.email} from {ip_address}")
                    messages.error(request, 'Account is disabled.')
            else:
                # Handle failed authentication
                if user:
                    user.failed_login_attempts += 1
                    user.last_failed_login = timezone.now()
                    
                    # Lock account after 5 failed attempts
                    if user.failed_login_attempts >= 5:
                        user.lock_account(30)  # 30 minutes
                        login_attempt.failure_reason = 'Too many attempts - account locked'
                        logger.warning(f"Account locked due to repeated failures: {user.email} from {ip_address}")
                        messages.error(request, 'Too many failed attempts. Account locked for 30 minutes.')
                    else:
                        login_attempt.failure_reason = 'Invalid credentials'
                        messages.error(request, 'Invalid credentials.')
                    
                    user.save()
                else:
                    login_attempt.failure_reason = 'User not found'
                    messages.error(request, 'Invalid credentials.')
                
                login_attempt.save()
                logger.warning(f"Failed login attempt: {login_data.email} from {ip_address}")
                
        except ValidationError as e:
            logger.warning(f"Invalid login data from {get_client_ip(request)}: {e}")
            messages.error(request, 'Invalid input data.')
        except Exception as e:
            logger.error(f"Login error: {e}")
            messages.error(request, 'An error occurred during login.')
    
    form = LoginForm()
    return render(request, 'auth/login.html', {'form': form})


@never_cache
@csrf_protect
@ratelimit(key='ip', rate='3/m', method='POST', block=True)
@require_http_methods(["GET", "POST"])
def mfa_verify_view(request):
    """Second factor authentication for users with MFA enabled."""
    # Check if user has passed first factor
    user_id = request.session.get('pre_2fa_user_id')
    session_ip = request.session.get('pre_2fa_ip')
    current_ip = get_client_ip(request)
    
    if not user_id or session_ip != current_ip:
        logger.warning(f"Invalid MFA verification attempt from {current_ip}")
        return redirect('auth:login')
    
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        logger.error(f"MFA verification for non-existent user: {user_id}")
        return redirect('auth:login')
    
    if request.method == 'POST':
        try:
            mfa_data = MFAVerifyRequest(**request.POST.dict())
            
            # Verify TOTP token
            from django_otp.util import match_token
            device = match_token(user, mfa_data.token)
            
            if device:
                # Complete login
                login(request, user)
                
                # Clean up session
                del request.session['pre_2fa_user_id']
                del request.session['pre_2fa_ip']
                
                # Update device usage
                device.last_used_at = timezone.now()
                device.save()
                
                logger.info(f"User {user.email} completed MFA verification from {current_ip}")
                create_audit_log(user, 'mfa_verify', f"MFA verification from {current_ip}", current_ip)
                
                next_url = request.GET.get('next', 'dashboard:home')
                return redirect(next_url)
            else:
                logger.warning(f"Invalid MFA token for user {user.email} from {current_ip}")
                messages.error(request, 'Invalid verification code.')
                
        except ValidationError as e:
            logger.warning(f"Invalid MFA data from {current_ip}: {e}")
            messages.error(request, 'Invalid verification code format.')
        except Exception as e:
            logger.error(f"MFA verification error: {e}")
            messages.error(request, 'Verification failed.')
    
    return render(request, 'auth/mfa_verify.html', {'user': user})


@login_required
@csrf_protect
@require_http_methods(["POST"])
def logout_view(request):
    """Log user out and clean up sessions and tokens."""
    user_email = request.user.email
    ip_address = get_client_ip(request)
    
    # Revoke OAuth2 tokens
    AccessToken.objects.filter(user=request.user).delete()
    
    logout(request)
    logger.info(f"User {user_email} logged out from {ip_address}")
    
    messages.success(request, 'You have been logged out successfully.')
    return redirect('auth:login')


@api_view(['POST'])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate='10/h', method='POST', block=True)
def api_login(request):
    """API endpoint that returns OAuth2 token for authenticated users."""
    try:
        login_data = LoginRequest(**request.data)
        
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
        
        user = authenticate(username=login_data.email, password=login_data.password)
        
        if user and user.is_active and not user.is_account_locked():
            # For API access, require that MFA is set up but don't enforce it here
            # API clients should use proper OAuth2 flow for MFA
            
            # Get or create OAuth2 application
            try:
                application = Application.objects.get(name='FinOps Dashboard API')
            except Application.DoesNotExist:
                logger.error("OAuth2 application not found")
                return Response(
                    {'error': 'Service configuration error'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Create access token (simplified for API - full OAuth2 flow recommended)
            from oauth2_provider.models import AccessToken
            import secrets
            
            token = AccessToken.objects.create(
                user=user,
                application=application,
                token=secrets.token_urlsafe(32),
                expires=timezone.now() + timedelta(seconds=1800),  # 30 minutes
                scope='read write'
            )
            
            logger.info(f"API login successful for {user.email} from {ip_address}")
            create_audit_log(user, 'api_login', f"API login from {ip_address}", ip_address)
            
            return Response({
                'access_token': token.token,
                'token_type': 'Bearer',
                'expires_in': 1800,
                'scope': 'read write'
            })
        else:
            logger.warning(f"Failed API login attempt: {login_data.email} from {ip_address}")
            return Response(
                {'error': 'Invalid credentials'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
            
    except ValidationError as e:
        return Response(
            {'error': 'Invalid input data', 'details': str(e)}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        logger.error(f"API login error: {e}")
        return Response(
            {'error': 'Authentication failed'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@login_required
@otp_required
@csrf_protect
def mfa_setup_view(request):
    """Let users configure TOTP authenticator apps."""
    if request.method == 'POST':
        form = MFASetupForm(request.POST)
        if form.is_valid():
            # Setup TOTP device
            from django_otp.plugins.otp_totp.models import TOTPDevice
            
            device = TOTPDevice.objects.create(
                user=request.user,
                name=form.cleaned_data['device_name'],
                confirmed=True
            )
            
            # Enable MFA for user
            request.user.is_mfa_enabled = True
            request.user.save()
            
            logger.info(f"MFA enabled for user {request.user.email}")
            create_audit_log(
                request.user, 
                'mfa_enabled', 
                f"MFA device '{device.name}' added", 
                get_client_ip(request)
            )
            
            messages.success(request, 'Two-factor authentication has been enabled.')
            return redirect('dashboard:home')
    else:
        form = MFASetupForm()
    
    return render(request, 'auth/mfa_setup.html', {'form': form})


# Error handlers
def error_400(request, exception):
    return render(request, 'errors/400.html', status=400)

def error_403(request, exception):
    return render(request, 'errors/403.html', status=403)

def error_404(request, exception):
    return render(request, 'errors/404.html', status=404)

def error_500(request):
    return render(request, 'errors/500.html', status=500)
