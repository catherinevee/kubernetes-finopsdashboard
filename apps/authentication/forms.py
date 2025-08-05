"""
Authentication forms with enhanced security validation.
"""
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from .models import User
from .utils import validate_password_strength, validate_aws_identifier


class LoginForm(forms.Form):
    """Secure login form with proper validation."""
    
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email',
            'autocomplete': 'email'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password',
            'autocomplete': 'current-password'
        })
    )
    remember_me = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )


class RegisterForm(UserCreationForm):
    """User registration form with enhanced validation."""
    
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email'
        })
    )
    first_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'First name'
        })
    )
    last_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Last name'
        })
    )
    
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'password1', 'password2')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Choose a username'
        })
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Create a strong password'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirm your password'
        })
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError("A user with this email already exists.")
        return email.lower()
    
    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        try:
            return validate_password_strength(password)
        except ValueError as e:
            raise ValidationError(str(e))


class MFASetupForm(forms.Form):
    """Multi-factor authentication setup form."""
    
    device_name = forms.CharField(
        max_length=100,
        help_text="Give your device a name (e.g., 'iPhone', 'Google Authenticator')",
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Device name'
        })
    )
    verification_code = forms.CharField(
        max_length=6,
        min_length=6,
        help_text="Enter the 6-digit code from your authenticator app",
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '000000',
            'pattern': '[0-9]{6}',
            'autocomplete': 'off'
        })
    )
    
    def clean_device_name(self):
        name = self.cleaned_data.get('device_name')
        # Sanitize device name
        import re
        name = re.sub(r'[^a-zA-Z0-9\s\-_]', '', name).strip()
        if not name:
            raise ValidationError("Please provide a valid device name.")
        return name
    
    def clean_verification_code(self):
        code = self.cleaned_data.get('verification_code')
        if not code.isdigit():
            raise ValidationError("Verification code must be numeric.")
        return code


class PasswordChangeForm(forms.Form):
    """Secure password change form."""
    
    current_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Current password',
            'autocomplete': 'current-password'
        })
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'New password',
            'autocomplete': 'new-password'
        })
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm new password',
            'autocomplete': 'new-password'
        })
    )
    
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_current_password(self):
        password = self.cleaned_data.get('current_password')
        if not self.user.check_password(password):
            raise ValidationError("Current password is incorrect.")
        return password
    
    def clean_new_password(self):
        password = self.cleaned_data.get('new_password')
        try:
            return validate_password_strength(password)
        except ValueError as e:
            raise ValidationError(str(e))
    
    def clean_confirm_password(self):
        new_password = self.cleaned_data.get('new_password')
        confirm_password = self.cleaned_data.get('confirm_password')
        
        if new_password and confirm_password and new_password != confirm_password:
            raise ValidationError("New passwords don't match.")
        
        return confirm_password
