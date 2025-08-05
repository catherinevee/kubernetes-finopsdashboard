"""
CLI wrapper that handles aws-finops-dashboard commands safely.

Prevents command injection attacks and validates all inputs before execution.
Every subprocess call uses parameter arrays instead of shell commands.
"""
import os
import subprocess
import shlex
import tempfile
import json
import logging
from typing import Dict, List, Optional, Union
from pathlib import Path
from django.conf import settings
from apps.authentication.utils import validate_aws_identifier, sanitize_filename

logger = logging.getLogger('finops_dashboard.cli')


class SecureCLIWrapper:
    """
    Wraps aws-finops-dashboard CLI execution with security controls.
    
    Built after several security incidents taught us that subprocess.run 
    with shell=True creates command injection vulnerabilities. This wrapper
    validates every parameter and uses argument arrays exclusively.
    
    The timeout limits prevent runaway processes from consuming resources.
    Resource limits stop memory bombs on Unix systems.
    """
    
    # Allowed CLI commands (whitelist approach)
    ALLOWED_COMMANDS = {
        'dashboard': {
            'base_cmd': ['aws-finops'],
            'required_params': ['--profiles', '--regions'],
            'optional_params': ['--output', '--config-file', '--time-range'],
            'allowed_outputs': ['json', 'csv', 'html'],
            'timeout': 300  # 5 minutes
        },
        'audit': {
            'base_cmd': ['aws-finops', '--audit'],
            'required_params': ['--profiles'],
            'optional_params': ['--output', '--config-file', '--regions'],
            'allowed_outputs': ['json', 'pdf', 'html'],
            'timeout': 600  # 10 minutes
        },
        'trend': {
            'base_cmd': ['aws-finops', '--trend'],
            'required_params': ['--profiles'],
            'optional_params': ['--time-range', '--output', '--regions'],
            'allowed_outputs': ['json', 'csv', 'html'],
            'allowed_time_ranges': ['1week', '1month', '3months', '6months', '1year'],
            'timeout': 450  # 7.5 minutes
        }
    }
    
    # Security limits
    MAX_PROFILES = 5
    MAX_REGIONS = 10
    MAX_OUTPUT_SIZE = 50 * 1024 * 1024  # 50MB
    
    def __init__(self):
        """Set up CLI wrapper with secure temp directory."""
        self.temp_dir = Path(tempfile.gettempdir()) / "finops_secure"
        self.temp_dir.mkdir(exist_ok=True, mode=0o700)  # Secure permissions
        
        # Verify aws-finops-dashboard is installed
        self._verify_cli_installation()
    
    def _verify_cli_installation(self):
        """Check that aws-finops-dashboard CLI exists and responds."""
        try:
            result = subprocess.run(
                ['aws-finops', '--version'],
                capture_output=True,
                shell=False,
                timeout=10,
                text=True
            )
            if result.returncode != 0:
                raise RuntimeError("aws-finops-dashboard CLI not properly installed")
            
            logger.info(f"AWS FinOps CLI verified: {result.stdout.strip()}")
            
        except FileNotFoundError:
            raise RuntimeError("aws-finops-dashboard CLI not found in PATH")
        except subprocess.TimeoutExpired:
            raise RuntimeError("aws-finops-dashboard CLI verification timeout")
    
    def validate_command_params(self, command_type: str, params: Dict) -> Dict:
        """
        Check parameters against whitelist and business rules.
        
        We learned the hard way that trusting user input leads to problems.
        Every parameter gets validated against known-good patterns before
        any CLI command runs.
        """
        if command_type not in self.ALLOWED_COMMANDS:
            raise ValueError(f"Invalid command type: {command_type}")
        
        cmd_config = self.ALLOWED_COMMANDS[command_type]
        validated_params = {}
        
        # Validate required parameters
        for req_param in cmd_config['required_params']:
            param_key = req_param.lstrip('-').replace('-', '_')
            if param_key not in params:
                raise ValueError(f"Required parameter missing: {req_param}")
            
            validated_params[param_key] = self._validate_parameter(
                req_param, params[param_key], cmd_config
            )
        
        # Validate optional parameters
        for opt_param in cmd_config.get('optional_params', []):
            param_key = opt_param.lstrip('-').replace('-', '_')
            if param_key in params:
                validated_params[param_key] = self._validate_parameter(
                    opt_param, params[param_key], cmd_config
                )
        
        return validated_params
    
    def _validate_parameter(self, param_name: str, param_value: Union[str, List], cmd_config: Dict):
        """Validate individual parameter based on its type and business rules."""
        param_key = param_name.lstrip('-').replace('-', '_')
        
        if param_name in ['--profiles', '--profile']:
            return self._validate_profiles(param_value)
        
        elif param_name in ['--regions', '--region']:
            return self._validate_regions(param_value)
        
        elif param_name == '--output':
            return self._validate_output_format(param_value, cmd_config)
        
        elif param_name == '--time-range':
            return self._validate_time_range(param_value, cmd_config)
        
        elif param_name == '--config-file':
            return self._validate_config_file(param_value)
        
        else:
            # Generic string validation
            return self._validate_generic_string(param_value)
    
    def _validate_profiles(self, profiles: Union[str, List]) -> List[str]:
        """Validate AWS profile names meet naming requirements."""
        if isinstance(profiles, str):
            profile_list = [p.strip() for p in profiles.split(',')]
        elif isinstance(profiles, list):
            profile_list = profiles
        else:
            raise ValueError("Profiles must be string or list")
        
        if len(profile_list) > self.MAX_PROFILES:
            raise ValueError(f"Too many profiles (max {self.MAX_PROFILES})")
        
        validated_profiles = []
        for profile in profile_list:
            if not profile:
                continue
            validated_profiles.append(validate_aws_identifier(profile, 'profile'))
        
        if not validated_profiles:
            raise ValueError("At least one valid profile required")
        
        return validated_profiles
    
    def _validate_regions(self, regions: Union[str, List]) -> List[str]:
        """Validate AWS region codes follow standard format."""
        if isinstance(regions, str):
            region_list = [r.strip() for r in regions.split(',')]
        elif isinstance(regions, list):
            region_list = regions
        else:
            raise ValueError("Regions must be string or list")
        
        if len(region_list) > self.MAX_REGIONS:
            raise ValueError(f"Too many regions (max {self.MAX_REGIONS})")
        
        validated_regions = []
        for region in region_list:
            if not region:
                continue
            validated_regions.append(validate_aws_identifier(region, 'region'))
        
        if not validated_regions:
            raise ValueError("At least one valid region required")
        
        return validated_regions
    
    def _validate_output_format(self, output_format: str, cmd_config: Dict) -> str:
        """Check output format against allowed values for this command."""
        if not isinstance(output_format, str):
            raise ValueError("Output format must be string")
        
        allowed_outputs = cmd_config.get('allowed_outputs', [])
        if output_format not in allowed_outputs:
            raise ValueError(f"Invalid output format. Allowed: {allowed_outputs}")
        
        return output_format
    
    def _validate_time_range(self, time_range: str, cmd_config: Dict) -> str:
        """Check time range fits within allowed values."""
        if not isinstance(time_range, str):
            raise ValueError("Time range must be string")
        
        allowed_ranges = cmd_config.get('allowed_time_ranges', [])
        if allowed_ranges and time_range not in allowed_ranges:
            raise ValueError(f"Invalid time range. Allowed: {allowed_ranges}")
        
        return time_range
    
    def _validate_config_file(self, config_path: str) -> str:
        """Sanitize config file path and verify it exists safely."""
        if not isinstance(config_path, str):
            raise ValueError("Config file path must be string")
        
        # Sanitize path to prevent directory traversal
        sanitized_path = sanitize_filename(os.path.basename(config_path))
        
        # Construct safe path within temp directory
        safe_path = self.temp_dir / sanitized_path
        
        if not safe_path.exists():
            raise ValueError("Configuration file not found")
        
        # Verify file size
        if safe_path.stat().st_size > 1024 * 1024:  # 1MB max
            raise ValueError("Configuration file too large")
        
        return str(safe_path)
    
    def _validate_generic_string(self, value: str) -> str:
        """Apply basic string validation for unknown parameters."""
        if not isinstance(value, str):
            raise ValueError("Parameter must be string")
        
        # Basic sanitization
        import re
        if not re.match(r'^[a-zA-Z0-9_.-]+$', value):
            raise ValueError("Invalid characters in parameter")
        
        if len(value) > 128:
            raise ValueError("Parameter too long")
        
        return value
    
    def build_command(self, command_type: str, validated_params: Dict) -> List[str]:
        """
        Build command array from validated parameters.
        
        Uses parameter arrays to prevent command injection attacks.
        String concatenation would allow attackers to inject shell commands.
        """
        cmd_config = self.ALLOWED_COMMANDS[command_type]
        command = cmd_config['base_cmd'].copy()
        
        # Add validated parameters
        for param_key, param_value in validated_params.items():
            param_flag = f"--{param_key.replace('_', '-')}"
            
            if isinstance(param_value, list):
                # Join list values with commas
                command.extend([param_flag, ','.join(param_value)])
            else:
                command.extend([param_flag, str(param_value)])
        
        logger.info(f"Built secure command: {' '.join(command)}")
        return command
    
    def execute_command(
        self, 
        command_type: str, 
        params: Dict, 
        output_file: Optional[str] = None
    ) -> Dict:
        """
        Run aws-finops-dashboard command with full security controls.
        
        Validates inputs, builds safe command arrays, enforces timeouts,
        and processes output within size limits.
        """
        try:
            # Step 1: Validate parameters
            validated_params = self.validate_command_params(command_type, params)
            
            # Step 2: Build secure command
            command = self.build_command(command_type, validated_params)
            
            # Step 3: Set up output redirection if needed
            if output_file:
                safe_output_path = self.temp_dir / sanitize_filename(output_file)
                validated_params['output_file'] = str(safe_output_path)
            
            # Step 4: Execute command with security constraints
            result = self._execute_subprocess(command, command_type)
            
            # Step 5: Process and validate output
            return self._process_command_output(result, command_type, validated_params)
            
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'command_type': command_type,
                'timestamp': self._get_timestamp()
            }
    
    def _execute_subprocess(self, command: List[str], command_type: str) -> subprocess.CompletedProcess:
        """
        Run subprocess with security constraints.
        
        Never uses shell=True because that enables command injection attacks.
        Timeouts prevent runaway processes. Environment cleanup removes
        variables that could be exploited.
        """
        cmd_config = self.ALLOWED_COMMANDS[command_type]
        timeout = cmd_config.get('timeout', 300)
        
        # Set up secure environment
        secure_env = os.environ.copy()
        
        # Remove potentially dangerous environment variables
        dangerous_vars = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH']
        for var in dangerous_vars:
            secure_env.pop(var, None)
        
        # Set working directory to temp directory
        working_dir = self.temp_dir
        
        logger.info(f"Executing command with timeout {timeout}s: {' '.join(command)}")
        
        try:
            # Execute with security constraints
            result = subprocess.run(
                command,
                capture_output=True,
                shell=False,  # CRITICAL: Never use shell=True
                timeout=timeout,
                text=True,
                env=secure_env,
                cwd=working_dir,
                # Additional security on Unix systems
                preexec_fn=self._set_subprocess_limits if os.name != 'nt' else None
            )
            
            # Check output size
            total_output_size = len(result.stdout) + len(result.stderr)
            if total_output_size > self.MAX_OUTPUT_SIZE:
                raise ValueError(f"Command output too large: {total_output_size} bytes")
            
            logger.info(f"Command completed with return code: {result.returncode}")
            return result
            
        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timeout after {timeout}s: {' '.join(command)}")
            raise ValueError(f"Command timed out after {timeout} seconds")
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with code {e.returncode}: {e}")
            raise ValueError(f"Command execution failed: {e}")
    
    def _set_subprocess_limits(self):
        """Apply resource limits on Unix systems to prevent resource exhaustion."""
        try:
            import resource
            
            # Set CPU time limit (10 minutes)
            resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
            
            # Set memory limit (1GB)
            resource.setrlimit(resource.RLIMIT_AS, (1024*1024*1024, 1024*1024*1024))
            
            # Prevent core dumps
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            
        except ImportError:
            # Resource module not available (Windows)
            pass
        except Exception as e:
            logger.warning(f"Failed to set subprocess limits: {e}")
    
    def _process_command_output(
        self, 
        result: subprocess.CompletedProcess, 
        command_type: str, 
        params: Dict
    ) -> Dict:
        """Process command output and parse JSON when possible."""
        success = result.returncode == 0
        
        output_data = {
            'success': success,
            'command_type': command_type,
            'return_code': result.returncode,
            'stdout': result.stdout[:10000] if result.stdout else '',  # Limit stdout
            'stderr': result.stderr[:5000] if result.stderr else '',   # Limit stderr
            'timestamp': self._get_timestamp(),
            'execution_metadata': {
                'command_length': len(' '.join(result.args)),
                'output_size': len(result.stdout) + len(result.stderr),
                'timeout_used': False
            }
        }
        
        if success:
            # Try to parse JSON output if applicable
            if params.get('output') in ['json'] and result.stdout:
                try:
                    parsed_output = json.loads(result.stdout)
                    output_data['parsed_output'] = parsed_output
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON output: {e}")
                    output_data['parse_error'] = str(e)
        
        else:
            logger.error(f"Command failed: {result.stderr}")
        
        return output_data
    
    def _get_timestamp(self) -> str:
        """Return current UTC timestamp in ISO format."""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'
    
    def create_config_file(self, config_data: Dict, filename: str) -> str:
        """
        Create config file safely in temp directory.
        
        Sanitizes filename to prevent directory traversal attacks.
        Sets restrictive permissions so only the owner can read the file.
        """
        # Sanitize filename
        safe_filename = sanitize_filename(filename)
        if not safe_filename.endswith('.json'):
            safe_filename += '.json'
        
        config_path = self.temp_dir / safe_filename
        
        try:
            # Validate configuration structure
            from apps.authentication.utils import validate_json_structure
            required_fields = ['profiles']
            
            if not validate_json_structure(config_data, required_fields):
                raise ValueError("Invalid configuration structure")
            
            # Write configuration file securely
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2)
            
            # Set secure permissions (owner read/write only)
            os.chmod(config_path, 0o600)
            
            logger.info(f"Created secure config file: {config_path}")
            return str(config_path)
            
        except Exception as e:
            logger.error(f"Failed to create config file: {e}")
            raise ValueError(f"Configuration file creation failed: {e}")
    
    def cleanup_temp_files(self, max_age_hours: int = 2):
        """Remove old temporary files to prevent disk space issues."""
        try:
            from datetime import datetime, timedelta
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            
            cleaned_count = 0
            for file_path in self.temp_dir.iterdir():
                if file_path.is_file():
                    file_age = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_age < cutoff_time:
                        file_path.unlink()
                        cleaned_count += 1
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} temporary files")
                
        except Exception as e:
            logger.error(f"Temp file cleanup failed: {e}")


# Global instance for CLI operations
cli_wrapper = SecureCLIWrapper()
