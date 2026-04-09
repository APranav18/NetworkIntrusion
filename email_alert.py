"""
Email Alert Module for AI-Based Network Intrusion Detection System
Sends email notifications when attacks are detected.

Features:
- Gmail SMTP integration
- HTML formatted emails
- Configurable alert severity thresholds
- Rate limiting to prevent email flooding
- Async email sending
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from datetime import datetime, timedelta
import threading
import queue
import time
import os


# Email Configuration
# UPDATE THESE WITH YOUR CREDENTIALS
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'your-email@gmail.com',
    'sender_password': 'your-app-password',  # Use Gmail App Password
    'recipient_email': 'admin@example.com',
    'enabled': False  # Set to True after configuring credentials
}

# Rate limiting configuration
RATE_LIMIT_CONFIG = {
    'max_emails_per_minute': 5,
    'cooldown_period': 60,  # seconds
    'aggregate_alerts': True,
    'aggregate_window': 30  # seconds
}


class EmailAlertManager:
    """
    Manages email alerts with rate limiting and aggregation.
    """
    
    def __init__(self, config=None):
        """
        Initialize the email alert manager.
        
        Args:
            config (dict): Email configuration dictionary
        """
        self.config = config or EMAIL_CONFIG
        self.rate_limit = RATE_LIMIT_CONFIG
        
        # Rate limiting tracking
        self.email_times = []
        self.pending_alerts = []
        self.last_aggregate_send = datetime.now()
        
        # Background email queue
        self.email_queue = queue.Queue()
        self.worker_thread = None
        self.running = False
        
    def start(self):
        """Start the background email worker."""
        if not self.config['enabled']:
            print("⚠ Email alerts disabled. Configure credentials to enable.")
            return
            
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        print("✓ Email alert service started")
        
    def stop(self):
        """Stop the background email worker."""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        print("✓ Email alert service stopped")
        
    def _worker(self):
        """Background worker to process email queue."""
        while self.running:
            try:
                # Check for pending emails
                try:
                    email_data = self.email_queue.get(timeout=1)
                    self._send_email(email_data)
                except queue.Empty:
                    pass
                
                # Check for aggregated alerts to send
                if self.rate_limit['aggregate_alerts']:
                    self._process_aggregated_alerts()
                    
            except Exception as e:
                print(f"Email worker error: {e}")
                time.sleep(5)
    
    def _process_aggregated_alerts(self):
        """Send aggregated alerts if window has passed."""
        now = datetime.now()
        window_passed = (now - self.last_aggregate_send).total_seconds() > \
                       self.rate_limit['aggregate_window']
        
        if window_passed and self.pending_alerts:
            self._send_aggregated_email(self.pending_alerts)
            self.pending_alerts = []
            self.last_aggregate_send = now
    
    def _check_rate_limit(self):
        """
        Check if we can send another email.
        
        Returns:
            bool: True if email can be sent
        """
        now = datetime.now()
        cutoff = now - timedelta(seconds=60)
        
        # Remove old timestamps
        self.email_times = [t for t in self.email_times if t > cutoff]
        
        # Check limit
        return len(self.email_times) < self.rate_limit['max_emails_per_minute']
    
    def queue_alert(self, attack_type, source_ip, confidence, details=None):
        """
        Queue an alert for sending.
        
        Args:
            attack_type (str): Type of attack detected
            source_ip (str): Source IP address
            confidence (float): Detection confidence
            details (str): Additional details
        """
        alert = {
            'timestamp': datetime.now(),
            'attack_type': attack_type,
            'source_ip': source_ip,
            'confidence': confidence,
            'details': details
        }
        
        if self.rate_limit['aggregate_alerts']:
            self.pending_alerts.append(alert)
        else:
            if self._check_rate_limit():
                self.email_queue.put(alert)
            else:
                print("⚠ Email rate limit reached, alert queued")
                self.pending_alerts.append(alert)
    
    def _send_email(self, alert):
        """
        Send a single alert email.
        
        Args:
            alert (dict): Alert data
        """
        if not self.config['enabled']:
            return
            
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"🚨 Network Intrusion Alert: {alert['attack_type']}"
            msg['From'] = self.config['sender_email']
            msg['To'] = self.config['recipient_email']
            
            # Create HTML content
            html_content = self._create_html_email(alert)
            text_content = self._create_text_email(alert)
            
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send email
            with smtplib.SMTP(self.config['smtp_server'], 
                             self.config['smtp_port']) as server:
                server.starttls()
                server.login(self.config['sender_email'], 
                           self.config['sender_password'])
                server.send_message(msg)
            
            self.email_times.append(datetime.now())
            print(f"✓ Alert email sent for {alert['attack_type']}")
            
        except Exception as e:
            print(f"✗ Failed to send email: {e}")
    
    def _send_aggregated_email(self, alerts):
        """
        Send an aggregated email for multiple alerts.
        
        Args:
            alerts (list): List of alert dictionaries
        """
        if not alerts or not self.config['enabled']:
            return
            
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"🚨 Network Intrusion Summary: {len(alerts)} attacks detected"
            msg['From'] = self.config['sender_email']
            msg['To'] = self.config['recipient_email']
            
            # Create content
            html_content = self._create_aggregated_html(alerts)
            text_content = self._create_aggregated_text(alerts)
            
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send email
            with smtplib.SMTP(self.config['smtp_server'], 
                             self.config['smtp_port']) as server:
                server.starttls()
                server.login(self.config['sender_email'], 
                           self.config['sender_password'])
                server.send_message(msg)
            
            self.email_times.append(datetime.now())
            print(f"✓ Aggregated alert email sent ({len(alerts)} alerts)")
            
        except Exception as e:
            print(f"✗ Failed to send aggregated email: {e}")
    
    def _create_html_email(self, alert):
        """
        Create HTML formatted email content.
        
        Args:
            alert (dict): Alert data
            
        Returns:
            str: HTML email content
        """
        severity_colors = {
            'DoS': '#e74c3c',
            'BruteForce': '#e67e22',
            'Botnet': '#9b59b6',
            'PortScan': '#f39c12',
            'WebAttack': '#c0392b'
        }
        
        color = severity_colors.get(alert['attack_type'], '#e74c3c')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, sans-serif;
                    background-color: #0a0e17;
                    color: #ffffff;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background: linear-gradient(145deg, #1a1f2e 0%, #0d1117 100%);
                    border-radius: 16px;
                    overflow: hidden;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                }}
                .header {{
                    background: linear-gradient(135deg, {color} 0%, {color}88 100%);
                    padding: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 24px;
                    text-transform: uppercase;
                    letter-spacing: 2px;
                }}
                .content {{
                    padding: 30px;
                }}
                .alert-badge {{
                    display: inline-block;
                    background: {color};
                    color: white;
                    padding: 8px 16px;
                    border-radius: 20px;
                    font-weight: bold;
                    margin-bottom: 20px;
                }}
                .info-row {{
                    display: flex;
                    justify-content: space-between;
                    padding: 15px 0;
                    border-bottom: 1px solid #2a3042;
                }}
                .info-label {{
                    color: #8b95a5;
                    font-weight: 500;
                }}
                .info-value {{
                    color: #ffffff;
                    font-weight: 600;
                }}
                .confidence-bar {{
                    height: 8px;
                    background: #2a3042;
                    border-radius: 4px;
                    overflow: hidden;
                    margin-top: 10px;
                }}
                .confidence-fill {{
                    height: 100%;
                    background: linear-gradient(90deg, {color}, #00d4ff);
                    width: {alert['confidence']*100}%;
                    border-radius: 4px;
                }}
                .footer {{
                    background: #0d1117;
                    padding: 20px;
                    text-align: center;
                    color: #5a6270;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>⚠️ INTRUSION ALERT</h1>
                </div>
                <div class="content">
                    <span class="alert-badge">{alert['attack_type']}</span>
                    
                    <div class="info-row">
                        <span class="info-label">Source IP</span>
                        <span class="info-value">{alert['source_ip']}</span>
                    </div>
                    
                    <div class="info-row">
                        <span class="info-label">Confidence</span>
                        <span class="info-value">{alert['confidence']*100:.1f}%</span>
                    </div>
                    <div class="confidence-bar">
                        <div class="confidence-fill"></div>
                    </div>
                    
                    <div class="info-row">
                        <span class="info-label">Timestamp</span>
                        <span class="info-value">{alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</span>
                    </div>
                    
                    {f'<div class="info-row"><span class="info-label">Details</span><span class="info-value">{alert["details"]}</span></div>' if alert.get('details') else ''}
                </div>
                <div class="footer">
                    AI-Based Network Intrusion Detection System<br>
                    This is an automated alert. Do not reply to this email.
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_text_email(self, alert):
        """
        Create plain text email content.
        
        Args:
            alert (dict): Alert data
            
        Returns:
            str: Plain text email content
        """
        text = f"""
NETWORK INTRUSION ALERT
=======================

Attack Type: {alert['attack_type']}
Source IP: {alert['source_ip']}
Confidence: {alert['confidence']*100:.1f}%
Timestamp: {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}
{f"Details: {alert['details']}" if alert.get('details') else ''}

This is an automated alert from AI-Based Network Intrusion Detection System.
        """
        
        return text.strip()
    
    def _create_aggregated_html(self, alerts):
        """
        Create HTML content for aggregated alerts.
        
        Args:
            alerts (list): List of alert dictionaries
            
        Returns:
            str: HTML content
        """
        # Group alerts by type
        from collections import Counter
        attack_counts = Counter(a['attack_type'] for a in alerts)
        
        rows = ""
        for alert in alerts[:20]:  # Limit to 20 alerts
            rows += f"""
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #2a3042;">{alert['attack_type']}</td>
                <td style="padding: 10px; border-bottom: 1px solid #2a3042;">{alert['source_ip']}</td>
                <td style="padding: 10px; border-bottom: 1px solid #2a3042;">{alert['confidence']*100:.1f}%</td>
                <td style="padding: 10px; border-bottom: 1px solid #2a3042;">{alert['timestamp'].strftime('%H:%M:%S')}</td>
            </tr>
            """
        
        summary = ", ".join(f"{count} {attack}" for attack, count in attack_counts.items())
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, sans-serif;
                    background-color: #0a0e17;
                    color: #ffffff;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 700px;
                    margin: 0 auto;
                    background: linear-gradient(145deg, #1a1f2e 0%, #0d1117 100%);
                    border-radius: 16px;
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                    padding: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 20px;
                }}
                .content {{
                    padding: 20px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                th {{
                    background: #2a3042;
                    padding: 12px;
                    text-align: left;
                }}
                .footer {{
                    padding: 20px;
                    text-align: center;
                    color: #5a6270;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>⚠️ {len(alerts)} ATTACKS DETECTED</h1>
                    <p style="margin: 10px 0 0; opacity: 0.9;">{summary}</p>
                </div>
                <div class="content">
                    <table>
                        <tr>
                            <th>Attack Type</th>
                            <th>Source IP</th>
                            <th>Confidence</th>
                            <th>Time</th>
                        </tr>
                        {rows}
                    </table>
                    {f'<p style="color: #8b95a5; margin-top: 15px;">... and {len(alerts) - 20} more alerts</p>' if len(alerts) > 20 else ''}
                </div>
                <div class="footer">
                    AI-Based Network Intrusion Detection System
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_aggregated_text(self, alerts):
        """
        Create plain text content for aggregated alerts.
        
        Args:
            alerts (list): List of alerts
            
        Returns:
            str: Plain text content
        """
        from collections import Counter
        attack_counts = Counter(a['attack_type'] for a in alerts)
        
        text = f"""
NETWORK INTRUSION SUMMARY
=========================

Total Attacks Detected: {len(alerts)}

Attack Breakdown:
"""
        
        for attack, count in attack_counts.items():
            text += f"  - {attack}: {count}\n"
        
        text += "\nRecent Alerts:\n"
        
        for alert in alerts[:10]:
            text += f"  [{alert['timestamp'].strftime('%H:%M:%S')}] {alert['attack_type']} from {alert['source_ip']} ({alert['confidence']*100:.1f}%)\n"
        
        return text.strip()


# Global alert manager instance
_alert_manager = None


def get_alert_manager():
    """
    Get or create the global alert manager instance.
    
    Returns:
        EmailAlertManager: Alert manager instance
    """
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = EmailAlertManager()
    return _alert_manager


def send_alert_email(attack_type, source_ip, confidence, details=None):
    """
    Convenience function to send an alert email.
    
    Args:
        attack_type (str): Type of attack
        source_ip (str): Source IP address
        confidence (float): Detection confidence
        details (str): Additional details
    """
    manager = get_alert_manager()
    manager.queue_alert(attack_type, source_ip, confidence, details)


def configure_email(sender_email, sender_password, recipient_email, 
                   smtp_server='smtp.gmail.com', smtp_port=587):
    """
    Configure email settings.
    
    Args:
        sender_email (str): Sender email address
        sender_password (str): Sender email password/app password
        recipient_email (str): Recipient email address
        smtp_server (str): SMTP server address
        smtp_port (int): SMTP server port
    """
    EMAIL_CONFIG.update({
        'sender_email': sender_email,
        'sender_password': sender_password,
        'recipient_email': recipient_email,
        'smtp_server': smtp_server,
        'smtp_port': smtp_port,
        'enabled': True
    })
    
    # Reinitialize manager
    global _alert_manager
    _alert_manager = EmailAlertManager()
    _alert_manager.start()


def test_email_config():
    """
    Test email configuration by sending a test email.
    
    Returns:
        bool: True if test email sent successfully
    """
    if not EMAIL_CONFIG['enabled']:
        print("⚠ Email alerts are not configured")
        return False
    
    try:
        msg = MIMEMultipart()
        msg['Subject'] = "✓ NIDS Email Alert Test"
        msg['From'] = EMAIL_CONFIG['sender_email']
        msg['To'] = EMAIL_CONFIG['recipient_email']
        
        body = """
        This is a test email from AI-Based Network Intrusion Detection System.
        
        If you received this email, your email alerts are configured correctly!
        
        You will receive automated alerts when attacks are detected on your network.
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], 
                         EMAIL_CONFIG['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['sender_email'], 
                        EMAIL_CONFIG['sender_password'])
            server.send_message(msg)
        
        print("✓ Test email sent successfully!")
        return True
        
    except Exception as e:
        print(f"✗ Test email failed: {e}")
        return False


if __name__ == "__main__":
    # Test the email alert system
    print("Email Alert Module Test")
    print("=" * 40)
    
    # Check configuration
    if EMAIL_CONFIG['enabled']:
        print("Email configuration is enabled")
        print(f"Sender: {EMAIL_CONFIG['sender_email']}")
        print(f"Recipient: {EMAIL_CONFIG['recipient_email']}")
        
        # Send test
        test_email_config()
    else:
        print("⚠ Email alerts are disabled")
        print("\nTo enable email alerts:")
        print("1. Edit EMAIL_CONFIG in this file")
        print("2. Set 'enabled' to True")
        print("3. Configure your Gmail credentials")
        print("\nNote: For Gmail, use an App Password:")
        print("https://support.google.com/accounts/answer/185833")
