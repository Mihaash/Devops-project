import requests
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup
import logging

class ThreatIntelligenceCollector:
    """Collects threat intelligence from various sources"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def fetch_recent_cves(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """Fetch recent CVEs from CVE database"""
        cves = []
        try:
            # Calculate date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            # For demo purposes, we'll simulate CVE data
            # In production, you would use a real CVE API
            simulated_cves = [
                {
                    "id": "CVE-2024-0001",
                    "description": "Critical vulnerability in Apache HTTP Server",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "published_date": (datetime.now() - timedelta(days=2)).isoformat(),
                    "affected_software": ["Apache", "HTTP Server"]
                },
                {
                    "id": "CVE-2024-0002", 
                    "description": "Buffer overflow in OpenSSL",
                    "severity": "HIGH",
                    "cvss_score": 8.5,
                    "published_date": (datetime.now() - timedelta(days=3)).isoformat(),
                    "affected_software": ["OpenSSL"]
                },
                {
                    "id": "CVE-2024-0003",
                    "description": "SQL injection vulnerability in PostgreSQL",
                    "severity": "MEDIUM", 
                    "cvss_score": 6.5,
                    "published_date": (datetime.now() - timedelta(days=5)).isoformat(),
                    "affected_software": ["PostgreSQL"]
                }
            ]
            
            cves = [cve for cve in simulated_cves 
                   if datetime.fromisoformat(cve["published_date"]) >= start_date]
            
            self.logger.info(f"Fetched {len(cves)} recent CVEs")
            
        except Exception as e:
            self.logger.error(f"Error fetching CVEs: {e}")
            
        return cves
    
    def fetch_malware_indicators(self) -> List[Dict[str, Any]]:
        """Fetch recent malware indicators"""
        indicators = []
        try:
            # Simulated malware indicators data
            # In production, you would integrate with real threat intelligence feeds
            simulated_indicators = [
                {
                    "type": "malicious_ip",
                    "value": "192.168.100.1",
                    "malware_family": "Emotet",
                    "first_seen": (datetime.now() - timedelta(hours=6)).isoformat(),
                    "confidence": 85,
                    "description": "Known C2 server for Emotet banking trojan"
                },
                {
                    "type": "malicious_domain",
                    "value": "malicious-example.com",
                    "malware_family": "TrickBot",
                    "first_seen": (datetime.now() - timedelta(hours=12)).isoformat(),
                    "confidence": 92,
                    "description": "Domain used for TrickBot distribution"
                },
                {
                    "type": "malicious_hash",
                    "value": "a1b2c3d4e5f6...",
                    "malware_family": "WannaCry",
                    "first_seen": (datetime.now() - timedelta(hours=24)).isoformat(),
                    "confidence": 95,
                    "description": "WannaCry ransomware executable hash"
                }
            ]
            
            indicators = simulated_indicators
            self.logger.info(f"Fetched {len(indicators)} malware indicators")
            
        except Exception as e:
            self.logger.error(f"Error fetching malware indicators: {e}")
            
        return indicators
    
    def analyze_internal_logs(self, log_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze internal logs for suspicious activities"""
        suspicious_activities = []
        
        try:
            for log_entry in log_data:
                # Check for failed login attempts
                if log_entry.get("event_type") == "login" and log_entry.get("status") == "failed":
                    if log_entry.get("failed_attempts", 0) > 5:
                        suspicious_activities.append({
                            "type": "brute_force_attempt",
                            "source_ip": log_entry.get("source_ip"),
                            "target_user": log_entry.get("username"),
                            "timestamp": log_entry.get("timestamp"),
                            "severity": "HIGH",
                            "description": f"Multiple failed login attempts for user {log_entry.get('username')}"
                        })
                
                # Check for unusual application behavior
                if log_entry.get("event_type") == "application":
                    if log_entry.get("cpu_usage", 0) > 90:
                        suspicious_activities.append({
                            "type": "unusual_cpu_usage",
                            "application": log_entry.get("application_name"),
                            "server": log_entry.get("server"),
                            "timestamp": log_entry.get("timestamp"),
                            "severity": "MEDIUM",
                            "description": f"High CPU usage detected for {log_entry.get('application_name')}"
                        })
                
                # Check for network anomalies
                if log_entry.get("event_type") == "network":
                    if log_entry.get("connections_per_second", 0) > 1000:
                        suspicious_activities.append({
                            "type": "network_anomaly",
                            "source_ip": log_entry.get("source_ip"),
                            "destination_port": log_entry.get("destination_port"),
                            "timestamp": log_entry.get("timestamp"),
                            "severity": "HIGH",
                            "description": f"Unusual network activity from {log_entry.get('source_ip')}"
                        })
            
            self.logger.info(f"Identified {len(suspicious_activities)} suspicious activities")
            
        except Exception as e:
            self.logger.error(f"Error analyzing internal logs: {e}")
            
        return suspicious_activities
    
    def generate_sample_logs(self) -> List[Dict[str, Any]]:
        """Generate sample internal log data for demonstration"""
        import random
        
        sample_logs = []
        current_time = datetime.now()
        
        # Generate sample login logs
        for i in range(20):
            sample_logs.append({
                "event_type": "login",
                "username": f"user{i % 5}",
                "source_ip": f"192.168.1.{100 + i % 50}",
                "status": random.choice(["success", "failed"]),
                "failed_attempts": random.randint(0, 10) if random.random() > 0.8 else 0,
                "timestamp": (current_time - timedelta(minutes=random.randint(0, 60))).isoformat()
            })
        
        # Generate sample application logs
        for i in range(15):
            sample_logs.append({
                "event_type": "application",
                "application_name": random.choice(["webapp", "database", "api-service"]),
                "server": random.choice(["web-server-01", "db-server-01"]),
                "cpu_usage": random.randint(20, 100),
                "memory_usage": random.randint(30, 95),
                "timestamp": (current_time - timedelta(minutes=random.randint(0, 60))).isoformat()
            })
        
        # Generate sample network logs
        for i in range(10):
            sample_logs.append({
                "event_type": "network",
                "source_ip": f"10.0.0.{i + 1}",
                "destination_port": random.choice([80, 443, 22, 3306, 5432]),
                "connections_per_second": random.randint(10, 1500),
                "timestamp": (current_time - timedelta(minutes=random.randint(0, 60))).isoformat()
            })
        
        return sample_logs
