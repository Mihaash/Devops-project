import yaml
import os
from typing import Dict, Any, List

class ConfigManager:
    """Configuration manager for the security dashboard"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as file:
                return yaml.safe_load(file)
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML configuration: {e}")
    
    def get_email_config(self) -> Dict[str, Any]:
        """Get email configuration"""
        return self.config.get('email', {})
    
    def get_dashboard_config(self) -> Dict[str, Any]:
        """Get dashboard configuration"""
        return self.config.get('dashboard', {})
    
    def get_threat_intel_config(self) -> Dict[str, Any]:
        """Get threat intelligence configuration"""
        return self.config.get('threat_intel', {})
    
    def get_alert_thresholds(self) -> Dict[str, Any]:
        """Get alert thresholds configuration"""
        return self.config.get('alert_thresholds', {})
    
    def get_assets(self) -> Dict[str, Any]:
        """Get asset inventory"""
        return self.config.get('assets', {})
    
    def get_recipient_emails(self) -> List[str]:
        """Get list of recipient emails"""
        email_config = self.get_email_config()
        return email_config.get('recipient_emails', [])
