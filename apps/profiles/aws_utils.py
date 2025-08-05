"""
Secure AWS credential management utilities.
"""
import os
import json
import boto3
import logging
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from cryptography.fernet import Fernet
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger('finops_dashboard.profiles')


class AWSCredentialManager:
    """Secure AWS credential management with encryption and rotation."""
    
    def __init__(self):
        """Initialize credential manager with encryption key."""
        self.encryption_key = self._get_or_create_encryption_key()
        self.fernet = Fernet(self.encryption_key)
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for credential storage."""
        key_env = os.environ.get('AWS_CREDENTIAL_ENCRYPTION_KEY')
        if key_env:
            return key_env.encode()
        
        # In production, this should come from a secure key management service
        # For development, generate a key (WARNING: not for production use)
        logger.warning("Using generated encryption key - not suitable for production")
        return Fernet.generate_key()
    
    def encrypt_credentials(self, credentials: Dict) -> bytes:
        """Encrypt credential data."""
        try:
            credential_json = json.dumps(credentials)
            return self.fernet.encrypt(credential_json.encode())
        except Exception as e:
            logger.error(f"Failed to encrypt credentials: {e}")
            raise ValueError("Credential encryption failed")
    
    def decrypt_credentials(self, encrypted_data: bytes) -> Dict:
        """Decrypt credential data."""
        try:
            decrypted_json = self.fernet.decrypt(encrypted_data).decode()
            return json.loads(decrypted_json)
        except Exception as e:
            logger.error(f"Failed to decrypt credentials: {e}")
            raise ValueError("Credential decryption failed")
    
    def create_sts_session(self, profile, duration_seconds: int = 3600) -> Dict:
        """Create temporary STS session with AssumeRole."""
        try:
            # Get base credentials
            credentials = self.decrypt_credentials(profile.credentials.encrypted_data)
            
            if profile.credentials.credential_type == 'iam_role':
                # Use AssumeRole for cross-account access
                sts_client = boto3.client(
                    'sts',
                    aws_access_key_id=credentials.get('access_key_id'),
                    aws_secret_access_key=credentials.get('secret_access_key'),
                    region_name=profile.default_region
                )
                
                assume_role_params = {
                    'RoleArn': profile.role_arn,
                    'RoleSessionName': f"finops-dashboard-{profile.id}",
                    'DurationSeconds': duration_seconds
                }
                
                if profile.external_id:
                    assume_role_params['ExternalId'] = profile.external_id
                
                response = sts_client.assume_role(**assume_role_params)
                
                temp_credentials = {
                    'access_key_id': response['Credentials']['AccessKeyId'],
                    'secret_access_key': response['Credentials']['SecretAccessKey'],
                    'session_token': response['Credentials']['SessionToken'],
                    'expires_at': response['Credentials']['Expiration'].isoformat()
                }
                
                # Update stored credentials with temporary ones
                encrypted_temp = self.encrypt_credentials(temp_credentials)
                profile.credentials.encrypted_data = encrypted_temp
                profile.credentials.expires_at = response['Credentials']['Expiration']
                profile.credentials.save()
                
                logger.info(f"Created STS session for profile {profile.name}")
                return temp_credentials
                
            elif profile.credentials.credential_type == 'instance_profile':
                # Use EC2 instance profile credentials
                return self._get_instance_profile_credentials()
            
            else:
                # Use existing credentials
                return credentials
                
        except (ClientError, BotoCoreError) as e:
            logger.error(f"AWS STS error for profile {profile.name}: {e}")
            raise ValueError(f"Failed to create AWS session: {e}")
        except Exception as e:
            logger.error(f"Unexpected error creating STS session: {e}")
            raise ValueError("Session creation failed")
    
    def _get_instance_profile_credentials(self) -> Dict:
        """Get credentials from EC2 instance profile."""
        try:
            # Use boto3's automatic credential detection
            session = boto3.Session()
            credentials = session.get_credentials()
            
            if not credentials:
                raise ValueError("No instance profile credentials available")
            
            return {
                'access_key_id': credentials.access_key,
                'secret_access_key': credentials.secret_key,
                'session_token': credentials.token,
            }
        except Exception as e:
            logger.error(f"Failed to get instance profile credentials: {e}")
            raise ValueError("Instance profile access failed")
    
    def test_credentials(self, profile) -> Dict:
        """Test AWS credentials by making a safe API call."""
        try:
            credentials = self.create_sts_session(profile, duration_seconds=900)  # 15 minutes
            
            # Create STS client to test credentials
            sts_client = boto3.client(
                'sts',
                aws_access_key_id=credentials['access_key_id'],
                aws_secret_access_key=credentials['secret_access_key'],
                aws_session_token=credentials.get('session_token'),
                region_name=profile.default_region
            )
            
            # Test with GetCallerIdentity (safe, read-only call)
            response = sts_client.get_caller_identity()
            
            return {
                'success': True,
                'account_id': response.get('Account'),
                'user_arn': response.get('Arn'),
                'user_id': response.get('UserId')
            }
            
        except Exception as e:
            logger.error(f"Credential test failed for profile {profile.name}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def rotate_credentials(self, profile) -> bool:
        """Rotate credentials if needed."""
        try:
            if not profile.credentials.needs_rotation():
                return True
            
            if profile.credentials.credential_type == 'sts_token':
                # Rotate STS token
                self.create_sts_session(profile)
                profile.credentials.last_rotated = timezone.now()
                profile.credentials.rotation_failures = 0
                profile.credentials.save()
                
                logger.info(f"Rotated credentials for profile {profile.name}")
                return True
            
            # Other credential types handled separately
            return True
            
        except Exception as e:
            profile.credentials.rotation_failures += 1
            profile.credentials.save()
            logger.error(f"Failed to rotate credentials for profile {profile.name}: {e}")
            return False


class AWSRegionValidator:
    """Validate AWS regions and check service availability."""
    
    @staticmethod
    def get_available_regions() -> List[Dict]:
        """Get list of available AWS regions with service information."""
        try:
            ec2 = boto3.client('ec2', region_name='us-east-1')
            response = ec2.describe_regions()
            
            regions = []
            for region in response['Regions']:
                regions.append({
                    'region': region['RegionName'],
                    'display_name': region['RegionName'].replace('-', ' ').title(),
                    'endpoint': region['Endpoint']
                })
            
            return sorted(regions, key=lambda x: x['region'])
            
        except Exception as e:
            logger.error(f"Failed to get AWS regions: {e}")
            return []
    
    @staticmethod
    def validate_region(region: str) -> bool:
        """Validate if region exists and is accessible."""
        try:
            ec2 = boto3.client('ec2', region_name=region)
            ec2.describe_regions(RegionNames=[region])
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidRegion':
                return False
            logger.warning(f"Region validation warning for {region}: {e}")
            return True  # Assume valid if we can't determine
        except Exception as e:
            logger.error(f"Region validation error for {region}: {e}")
            return False
    
    @staticmethod
    def check_service_availability(region: str, services: List[str]) -> Dict:
        """Check if specific AWS services are available in a region."""
        availability = {}
        
        for service in services:
            try:
                if service == 'ce':  # Cost Explorer
                    # Cost Explorer is global but data is regionalized
                    client = boto3.client('ce', region_name='us-east-1')
                    client.get_cost_and_usage(
                        TimePeriod={
                            'Start': (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d'),
                            'End': datetime.now().strftime('%Y-%m-%d')
                        },
                        Granularity='DAILY',
                        Metrics=['BlendedCost']
                    )
                    availability[service] = True
                    
                elif service == 'budgets':
                    client = boto3.client('budgets', region_name='us-east-1')
                    client.describe_budgets(AccountId='123456789012', MaxResults=1)
                    availability[service] = True
                    
                elif service == 'ec2':
                    client = boto3.client('ec2', region_name=region)
                    client.describe_instances(MaxResults=1)
                    availability[service] = True
                    
                else:
                    # Generic service check
                    client = boto3.client(service, region_name=region)
                    availability[service] = True
                    
            except ClientError as e:
                if e.response['Error']['Code'] in ['InvalidAction', 'UnauthorizedOperation']:
                    availability[service] = True  # Service exists but we lack permissions
                else:
                    availability[service] = False
            except Exception:
                availability[service] = False
        
        return availability


def validate_aws_profile_permissions(profile) -> Dict:
    """Validate that profile has required permissions for FinOps operations."""
    required_permissions = [
        'ce:GetCostAndUsage',
        'ce:GetDimensionValues',
        'budgets:ViewBudget',
        'ec2:DescribeInstances',
        'sts:GetCallerIdentity'
    ]
    
    credential_manager = AWSCredentialManager()
    
    try:
        # Test basic connectivity
        test_result = credential_manager.test_credentials(profile)
        if not test_result['success']:
            return {
                'valid': False,
                'error': test_result['error'],
                'missing_permissions': required_permissions
            }
        
        # Test specific permissions (simplified check)
        credentials = credential_manager.create_sts_session(profile)
        
        # Test Cost Explorer access
        try:
            ce_client = boto3.client(
                'ce',
                aws_access_key_id=credentials['access_key_id'],
                aws_secret_access_key=credentials['secret_access_key'],
                aws_session_token=credentials.get('session_token'),
                region_name='us-east-1'  # Cost Explorer is global
            )
            
            # Simple test query
            ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': (datetime.now() - timedelta(days=2)).strftime('%Y-%m-%d'),
                    'End': (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
                },
                Granularity='DAILY',
                Metrics=['BlendedCost']
            )
            
            return {
                'valid': True,
                'account_id': test_result['account_id'],
                'permissions_verified': ['ce:GetCostAndUsage', 'sts:GetCallerIdentity']
            }
            
        except ClientError as e:
            missing_perms = []
            if 'AccessDenied' in str(e):
                missing_perms = ['ce:GetCostAndUsage']
            
            return {
                'valid': False,
                'error': f"Missing permissions: {e}",
                'missing_permissions': missing_perms
            }
    
    except Exception as e:
        return {
            'valid': False,
            'error': str(e),
            'missing_permissions': required_permissions
        }
