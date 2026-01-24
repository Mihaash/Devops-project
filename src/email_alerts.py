import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, List, Any
from datetime import datetime
import logging
import hashlib

class EmailAlertSystem:
    """Handles email notifications for high and critical security alerts"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.email_config = config.get("email", {})
        self.logger = logging.getLogger(__name__)
        self.sent_alert_hashes = set()  # Track sent alerts to avoid duplicates
        
    def send_alert_notification(self, alert: Dict[str, Any]) -> bool:
        """Send email notification for a single alert"""
        try:
            # Only send notifications for High and Critical alerts
            if alert["severity"] not in ["High", "Critical"]:
                return False
            
            # Check if we've already sent this alert
            alert_hash = self._generate_alert_hash(alert)
            if alert_hash in self.sent_alert_hashes:
                self.logger.info(f"Alert already sent: {alert['id']}")
                return False
            
            # Create email message
            message = self._create_alert_email(alert)
            
            # Send email
            success = self._send_email(message)
            
            if success:
                self.sent_alert_hashes.add(alert_hash)
                self.logger.info(f"Alert notification sent: {alert['id']}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error sending alert notification: {e}")
            return False
    
    def send_batch_alert_summary(self, alerts: List[Dict[str, Any]]) -> bool:
        """Send a summary email for multiple alerts"""
        try:
            # Filter for High and Critical alerts
            high_critical_alerts = [alert for alert in alerts 
                                   if alert["severity"] in ["High", "Critical"]]
            
            if not high_critical_alerts:
                return False
            
            # Check for new alerts (not already sent)
            new_alerts = []
            for alert in high_critical_alerts:
                alert_hash = self._generate_alert_hash(alert)
                if alert_hash not in self.sent_alert_hashes:
                    new_alerts.append(alert)
            
            if not new_alerts:
                self.logger.info("No new alerts to send in batch")
                return False
            
            # Create batch email message
            message = self._create_batch_email(new_alerts)
            
            # Send email
            success = self._send_email(message)
            
            if success:
                # Mark all alerts as sent
                for alert in new_alerts:
                    self.sent_alert_hashes.add(self._generate_alert_hash(alert))
                self.logger.info(f"Batch alert summary sent for {len(new_alerts)} alerts")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error sending batch alert summary: {e}")
            return False
    
    def _create_alert_email(self, alert: Dict[str, Any]) -> MIMEMultipart:
        """Create email message for a single alert"""
        message = MIMEMultipart("alternative")
        message["Subject"] = f"🚨 SECURITY ALERT: {alert['severity']} - {alert['title']}"
        message["From"] = self.email_config.get("sender_email")
        message["To"] = ", ".join(self.email_config.get("recipient_emails", []))
        
        # Create HTML email body
        html_body = self._generate_alert_html(alert)
        
        # Create plain text email body
        text_body = self._generate_alert_text(alert)
        
        # Attach both plain text and HTML versions
        message.attach(MIMEText(text_body, "plain"))
        message.attach(MIMEText(html_body, "html"))
        
        return message
    
    def _create_batch_email(self, alerts: List[Dict[str, Any]]) -> MIMEMultipart:
        """Create email message for multiple alerts"""
        message = MIMEMultipart("alternative")
        message["Subject"] = f"🚨 SECURITY ALERT SUMMARY: {len(alerts)} New High/Critical Alerts"
        message["From"] = self.email_config.get("sender_email")
        message["To"] = ", ".join(self.email_config.get("recipient_emails", []))
        
        # Create HTML email body
        html_body = self._generate_batch_html(alerts)
        
        # Create plain text email body
        text_body = self._generate_batch_text(alerts)
        
        # Attach both plain text and HTML versions
        message.attach(MIMEText(text_body, "plain"))
        message.attach(MIMEText(html_body, "html"))
        
        return message
    
    def _generate_alert_html(self, alert: Dict[str, Any]) -> str:
        """Generate HTML content for single alert email"""
        severity_colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745"
        }
        
        severity_color = severity_colors.get(alert["severity"], "#6c757d")
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f8f9fa; }}
                .container {{ max-width: 600px; margin: 20px auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .header {{ background-color: {severity_color}; color: white; padding: 15px; border-radius: 8px 8px 0 0; text-align: center; }}
                .content {{ padding: 20px; }}
                .alert-info {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }}
                .severity {{ color: {severity_color}; font-weight: bold; }}
                .recommendations {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; margin: 10px 0; }}
                .footer {{ text-align: center; color: #6c757d; margin-top: 20px; font-size: 12px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f8f9fa; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 SECURITY ALERT</h1>
                    <h2>{alert['severity']} Priority</h2>
                </div>
                
                <div class="content">
                    <h3>{alert['title']}</h3>
                    <p><strong>Description:</strong> {alert['description']}</p>
                    
                    <div class="alert-info">
                        <h4>Alert Details</h4>
                        <table>
                            <tr><th>Alert ID:</th><td>{alert['id']}</td></tr>
                            <tr><th>Severity:</th><td class="severity">{alert['severity']}</td></tr>
                            <tr><th>Type:</th><td>{alert['type']}</td></tr>
                            <tr><th>Target Asset:</th><td>{alert['target_asset']}</td></tr>
                            <tr><th>Source IP:</th><td>{alert.get('source_ip', alert.get('target_ip', 'N/A'))}</td></tr>
                            <tr><th>First Seen:</th><td>{self._format_timestamp(alert['first_seen'])}</td></tr>
                            <tr><th>Status:</th><td>{alert['status']}</td></tr>
                        </table>
                    </div>
                    
                    <div class="recommendations">
                        <h4>🔧 Recommended Actions</h4>
                        <ul>
        """
        
        for recommendation in alert.get('recommendations', []):
            html += f"<li>{recommendation}</li>"
        
        html += f"""
                        </ul>
                    </div>
                    
                    <p><strong>Immediate Action Required:</strong> Please investigate this alert immediately and follow the recommended actions to mitigate the threat.</p>
                </div>
                
                <div class="footer">
                    <p>This alert was generated by the Security Operations Center monitoring system.</p>
                    <p>For assistance, contact the security team or check the SOC dashboard.</p>
                    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_batch_html(self, alerts: List[Dict[str, Any]]) -> str:
        """Generate HTML content for batch alert email"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f8f9fa; }
                .container { max-width: 800px; margin: 20px auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .header { background-color: #dc3545; color: white; padding: 15px; border-radius: 8px 8px 0 0; text-align: center; }
                .content { padding: 20px; }
                .alert-item { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #dc3545; }
                .critical { border-left-color: #dc3545; }
                .high { border-left-color: #fd7e14; }
                .severity { font-weight: bold; }
                .footer { text-align: center; color: #6c757d; margin-top: 20px; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 SECURITY ALERT SUMMARY</h1>
                    <h2>{len(alerts)} New High/Critical Alerts Detected</h2>
                </div>
                
                <div class="content">
                    <p>The following security alerts have been detected and require your immediate attention:</p>
        """
        
        for alert in alerts:
            severity_class = alert['severity'].lower()
            html += f"""
                    <div class="alert-item {severity_class}">
                        <h3>{alert['title']}</h3>
                        <p><strong>Severity:</strong> <span class="severity">{alert['severity']}</span></p>
                        <p><strong>Type:</strong> {alert['type']}</p>
                        <p><strong>Target Asset:</strong> {alert['target_asset']}</p>
                        <p><strong>Description:</strong> {alert['description']}</p>
                        <p><strong>First Seen:</strong> {self._format_timestamp(alert['first_seen'])}</p>
                    </div>
            """
        
        html += f"""
                    <p><strong>Immediate Action Required:</strong> Please log into the SOC dashboard to review these alerts and take appropriate action.</p>
                    <p><strong>Dashboard Access:</strong> http://localhost:8050</p>
                </div>
                
                <div class="footer">
                    <p>This alert summary was generated by the Security Operations Center monitoring system.</p>
                    <p>For assistance, contact the security team.</p>
                    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_alert_text(self, alert: Dict[str, Any]) -> str:
        """Generate plain text content for single alert email"""
        text = f"""
SECURITY ALERT - {alert['severity']} PRIORITY

Alert ID: {alert['id']}
Title: {alert['title']}
Severity: {alert['severity']}
Type: {alert['type']}
Target Asset: {alert['target_asset']}
Source IP: {alert.get('source_ip', alert.get('target_ip', 'N/A'))}
First Seen: {self._format_timestamp(alert['first_seen'])}
Status: {alert['status']}

Description:
{alert['description']}

Recommended Actions:
"""
        
        for recommendation in alert.get('recommendations', []):
            text += f"- {recommendation}\n"
        
        text += f"""
Immediate Action Required: Please investigate this alert immediately and follow the recommended actions.

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Security Operations Center
"""
        
        return text
    
    def _generate_batch_text(self, alerts: List[Dict[str, Any]]) -> str:
        """Generate plain text content for batch alert email"""
        text = f"""
SECURITY ALERT SUMMARY

{len(alerts)} New High/Critical Alerts Detected

The following security alerts have been detected and require your immediate attention:

"""
        
        for i, alert in enumerate(alerts, 1):
            text += f"""
{i}. {alert['title']}
   Severity: {alert['severity']}
   Type: {alert['type']}
   Target Asset: {alert['target_asset']}
   Description: {alert['description']}
   First Seen: {self._format_timestamp(alert['first_seen'])}

"""
        
        text += f"""
Immediate Action Required: Please log into the SOC dashboard to review these alerts and take appropriate action.

Dashboard Access: http://localhost:8050

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Security Operations Center
"""
        
        return text
    
    def _send_email(self, message: MIMEMultipart) -> bool:
        """Send email using SMTP"""
        try:
            sender_email = self.email_config.get("sender_email")
            sender_password = self.email_config.get("sender_password")
            smtp_server = self.email_config.get("smtp_server")
            smtp_port = self.email_config.get("smtp_port", 587)
            
            if not all([sender_email, sender_password, smtp_server]):
                self.logger.error("Email configuration incomplete")
                return False
            
            # Create SMTP session
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            
            # Send email
            recipients = self.email_config.get("recipient_emails", [])
            server.sendmail(sender_email, recipients, message.as_string())
            
            # Close session
            server.quit()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending email: {e}")
            return False
    
    def _generate_alert_hash(self, alert: Dict[str, Any]) -> str:
        """Generate hash for alert deduplication"""
        hash_fields = [
            alert.get('type', ''),
            alert.get('title', ''),
            alert.get('target_asset', ''),
            alert.get('first_seen', '')
        ]
        
        hash_string = "|".join(str(field) for field in hash_fields)
        return hashlib.md5(hash_string.encode()).hexdigest()
    
    def _format_timestamp(self, timestamp: str) -> str:
        """Format timestamp for display"""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            return timestamp
