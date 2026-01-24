from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import uuid
import hashlib
import logging
from enum import Enum

class AlertSeverity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class AlertType(Enum):
    VULNERABILITY = "Vulnerability"
    MALWARE = "Malware"
    SUSPICIOUS_ACTIVITY = "Suspicious Activity"
    NETWORK_ANOMALY = "Network Anomaly"
    BRUTE_FORCE = "Brute Force"

class AlertSystem:
    """Manages security alert generation, classification, and deduplication"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.alerts = []
        self.alert_hashes = set()  # For deduplication
        self.logger = logging.getLogger(__name__)
        self.alert_thresholds = config.get("alert_thresholds", {})
        
    def generate_alerts_from_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate alerts from correlated vulnerabilities"""
        alerts = []
        
        try:
            for vuln in vulnerabilities:
                alert = self._create_vulnerability_alert(vuln)
                if alert and not self._is_duplicate_alert(alert):
                    alerts.append(alert)
                    self.alert_hashes.add(self._generate_alert_hash(alert))
            
            self.logger.info(f"Generated {len(alerts)} vulnerability alerts")
            
        except Exception as e:
            self.logger.error(f"Error generating vulnerability alerts: {e}")
            
        return alerts
    
    def generate_alerts_from_malware(self, malware_threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate alerts from correlated malware threats"""
        alerts = []
        
        try:
            for threat in malware_threats:
                alert = self._create_malware_alert(threat)
                if alert and not self._is_duplicate_alert(alert):
                    alerts.append(alert)
                    self.alert_hashes.add(self._generate_alert_hash(alert))
            
            self.logger.info(f"Generated {len(alerts)} malware alerts")
            
        except Exception as e:
            self.logger.error(f"Error generating malware alerts: {e}")
            
        return alerts
    
    def generate_alerts_from_activities(self, activities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate alerts from suspicious activities"""
        alerts = []
        
        try:
            for activity in activities:
                alert = self._create_activity_alert(activity)
                if alert and not self._is_duplicate_alert(alert):
                    alerts.append(alert)
                    self.alert_hashes.add(self._generate_alert_hash(alert))
            
            self.logger.info(f"Generated {len(alerts)} activity alerts")
            
        except Exception as e:
            self.logger.error(f"Error generating activity alerts: {e}")
            
        return alerts
    
    def _create_vulnerability_alert(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create an alert from vulnerability data"""
        try:
            severity = AlertSeverity[vulnerability["remediation_priority"].upper()]
            
            alert = {
                "id": str(uuid.uuid4()),
                "type": AlertType.VULNERABILITY.value,
                "severity": severity.value,
                "title": f"Vulnerability Detected: {vulnerability['cve_id']}",
                "description": vulnerability["description"],
                "source": "CVE Database",
                "target_asset": vulnerability["affected_asset"],
                "target_ip": vulnerability.get("asset_ip", "N/A"),
                "cvss_score": vulnerability["cvss_score"],
                "affected_software": vulnerability["affected_software"],
                "first_seen": vulnerability["published_date"],
                "last_seen": datetime.now().isoformat(),
                "status": "Active",
                "recommendations": self._get_vulnerability_recommendations(vulnerability),
                "metadata": {
                    "cve_id": vulnerability["cve_id"],
                    "remediation_priority": vulnerability["remediation_priority"]
                }
            }
            
            return alert
            
        except Exception as e:
            self.logger.error(f"Error creating vulnerability alert: {e}")
            return None
    
    def _create_malware_alert(self, threat: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create an alert from malware threat data"""
        try:
            severity = AlertSeverity[threat["severity"].upper()]
            
            alert = {
                "id": str(uuid.uuid4()),
                "type": AlertType.MALWARE.value,
                "severity": severity.value,
                "title": f"Malware Threat: {threat['malware_family']}",
                "description": threat["description"],
                "source": "Threat Intelligence",
                "target_asset": threat["affected_asset"],
                "target_ip": threat.get("asset_ip", "N/A"),
                "indicator_type": threat["indicator_type"],
                "indicator_value": threat["indicator_value"],
                "malware_family": threat["malware_family"],
                "confidence": threat["confidence"],
                "first_seen": threat["first_seen"],
                "last_seen": datetime.now().isoformat(),
                "status": "Active",
                "recommendations": self._get_malware_recommendations(threat),
                "metadata": {
                    "threat_id": str(uuid.uuid4()),
                    "confidence": threat["confidence"]
                }
            }
            
            return alert
            
        except Exception as e:
            self.logger.error(f"Error creating malware alert: {e}")
            return None
    
    def _create_activity_alert(self, activity: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create an alert from suspicious activity data"""
        try:
            severity = AlertSeverity[activity["severity"].upper()]
            
            # Map activity types to alert types
            activity_type_mapping = {
                "brute_force_attempt": AlertType.BRUTE_FORCE,
                "unusual_cpu_usage": AlertType.SUSPICIOUS_ACTIVITY,
                "network_anomaly": AlertType.NETWORK_ANOMALY
            }
            
            alert_type = activity_type_mapping.get(activity["type"], AlertType.SUSPICIOUS_ACTIVITY)
            
            alert = {
                "id": str(uuid.uuid4()),
                "type": alert_type.value,
                "severity": severity.value,
                "title": f"Suspicious Activity: {activity['type'].replace('_', ' ').title()}",
                "description": activity["description"],
                "source": "Internal Monitoring",
                "target_asset": activity.get("server", activity.get("application", "Unknown")),
                "source_ip": activity.get("source_ip", "N/A"),
                "target_user": activity.get("target_user", "N/A"),
                "first_seen": activity["timestamp"],
                "last_seen": datetime.now().isoformat(),
                "status": "Active",
                "recommendations": self._get_activity_recommendations(activity),
                "metadata": {
                    "activity_type": activity["type"],
                    "original_timestamp": activity["timestamp"]
                }
            }
            
            return alert
            
        except Exception as e:
            self.logger.error(f"Error creating activity alert: {e}")
            return None
    
    def _get_vulnerability_recommendations(self, vulnerability: Dict[str, Any]) -> List[str]:
        """Generate recommendations for vulnerability alerts"""
        recommendations = []
        
        if vulnerability["remediation_priority"] == "CRITICAL":
            recommendations.append("Apply security patches immediately")
            recommendations.append("Consider isolating affected system until patched")
        elif vulnerability["remediation_priority"] == "HIGH":
            recommendations.append("Apply patches within 7 days")
            recommendations.append("Monitor affected system for exploitation attempts")
        elif vulnerability["remediation_priority"] == "MEDIUM":
            recommendations.append("Schedule patches in next maintenance window")
            recommendations.append("Implement compensating controls if patching delayed")
        else:
            recommendations.append("Include in regular patch cycle")
        
        recommendations.append(f"Review {vulnerability['cve_id']} for specific patch information")
        
        return recommendations
    
    def _get_malware_recommendations(self, threat: Dict[str, Any]) -> List[str]:
        """Generate recommendations for malware alerts"""
        recommendations = []
        
        if threat["indicator_type"] == "malicious_ip":
            recommendations.append("Block malicious IP address in firewall")
            recommendations.append("Review network logs for connections to this IP")
        elif threat["indicator_type"] == "malicious_domain":
            recommendations.append("Block malicious domain in DNS")
            recommendations.append("Check for DNS cache poisoning")
        elif threat["indicator_type"] == "malicious_hash":
            recommendations.append("Scan systems for malicious file hash")
            recommendations.append("Review endpoint detection logs")
        
        if threat["confidence"] >= 90:
            recommendations.append("Immediate containment recommended")
        elif threat["confidence"] >= 70:
            recommendations.append("Enhanced monitoring recommended")
        
        recommendations.append(f"Research {threat['malware_family']} for additional IOCs")
        
        return recommendations
    
    def _get_activity_recommendations(self, activity: Dict[str, Any]) -> List[str]:
        """Generate recommendations for suspicious activity alerts"""
        recommendations = []
        
        if activity["type"] == "brute_force_attempt":
            recommendations.append("Lock affected user account temporarily")
            recommendations.append("Implement account lockout policy")
            recommendations.append("Review source IP for blocking")
        elif activity["type"] == "unusual_cpu_usage":
            recommendations.append("Investigate application performance")
            recommendations.append("Check for cryptocurrency mining malware")
            recommendations.append("Monitor system resources")
        elif activity["type"] == "network_anomaly":
            recommendations.append("Analyze network traffic patterns")
            recommendations.append("Check for DDoS attack")
            recommendations.append("Review firewall logs")
        
        return recommendations
    
    def _generate_alert_hash(self, alert: Dict[str, Any]) -> str:
        """Generate hash for alert deduplication"""
        # Create hash based on key fields to identify duplicates
        hash_fields = []
        
        if alert["type"] == AlertType.VULNERABILITY.value:
            hash_fields = [
                alert["type"],
                alert["metadata"]["cve_id"],
                alert["target_asset"]
            ]
        elif alert["type"] == AlertType.MALWARE.value:
            hash_fields = [
                alert["type"],
                alert["indicator_value"],
                alert["malware_family"]
            ]
        else:
            hash_fields = [
                alert["type"],
                alert["source_ip"],
                alert["target_asset"]
            ]
        
        hash_string = "|".join(str(field) for field in hash_fields)
        return hashlib.md5(hash_string.encode()).hexdigest()
    
    def _is_duplicate_alert(self, alert: Dict[str, Any]) -> bool:
        """Check if alert is a duplicate"""
        alert_hash = self._generate_alert_hash(alert)
        
        # Check if we've seen this alert recently
        duplicate_window = self.alert_thresholds.get("duplicate_alert_window", 3600)
        current_time = datetime.now()
        
        # Check existing alerts for duplicates within the time window
        for existing_alert in self.alerts:
            if (self._generate_alert_hash(existing_alert) == alert_hash and
                current_time - datetime.fromisoformat(existing_alert["last_seen"]) < timedelta(seconds=duplicate_window)):
                return True
        
        return False
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics for dashboard"""
        stats = {
            "total_alerts": len(self.alerts),
            "by_severity": {},
            "by_type": {},
            "active_alerts": 0,
            "recent_alerts": 0
        }
        
        now = datetime.now()
        recent_threshold = now - timedelta(hours=24)
        
        for alert in self.alerts:
            # Count by severity
            severity = alert["severity"]
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            # Count by type
            alert_type = alert["type"]
            stats["by_type"][alert_type] = stats["by_type"].get(alert_type, 0) + 1
            
            # Count active alerts
            if alert["status"] == "Active":
                stats["active_alerts"] += 1
            
            # Count recent alerts (last 24 hours)
            if datetime.fromisoformat(alert["first_seen"]) > recent_threshold:
                stats["recent_alerts"] += 1
        
        return stats
    
    def add_alerts(self, alerts: List[Dict[str, Any]]) -> None:
        """Add alerts to the system"""
        self.alerts.extend(alerts)
        
        # Limit total alerts to prevent memory issues
        max_alerts = 1000
        if len(self.alerts) > max_alerts:
            self.alerts = self.alerts[-max_alerts:]
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get most recent alerts"""
        sorted_alerts = sorted(self.alerts, key=lambda x: x["first_seen"], reverse=True)
        return sorted_alerts[:limit]
