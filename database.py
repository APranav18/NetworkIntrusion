"""
Database Module for AI-Based Network Intrusion Detection System
Handles all SQLite database operations including user management and attack logging.
"""

import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os

# Database Configuration
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nids.db')


def get_db_connection():
    """
    Establish and return a SQLite database connection.
    
    Returns:
        sqlite3.Connection: Database connection object or None if failed
    """
    try:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row  # Enable dict-like access
        return connection
    except Exception as e:
        print(f"Error connecting to SQLite Database: {e}")
    return None


def init_database():
    """
    Initialize the database by creating required tables if they don't exist.
    Creates: users table, logs table, alerts table, statistics table
    """
    connection = None
    cursor = None
    try:
        connection = sqlite3.connect(DB_PATH)
        cursor = connection.cursor()
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create logs table for attack detection records
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                attack_type TEXT,
                status TEXT,
                confidence REAL,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                details TEXT
            )
        """)
        
        # Create alerts table for real-time notifications
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER,
                severity TEXT,
                message TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (log_id) REFERENCES logs(id) ON DELETE CASCADE
            )
        """)
        
        # Create statistics table for dashboard metrics
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE UNIQUE,
                total_packets INTEGER DEFAULT 0,
                normal_count INTEGER DEFAULT 0,
                dos_count INTEGER DEFAULT 0,
                bruteforce_count INTEGER DEFAULT 0,
                botnet_count INTEGER DEFAULT 0,
                portscan_count INTEGER DEFAULT 0,
                webattack_count INTEGER DEFAULT 0
            )
        """)
        
        connection.commit()
        print("[OK] Database initialized successfully!")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def create_user(username, password, email=None):
    """
    Create a new user with hashed password.
    
    Args:
        username (str): Username for the new user
        password (str): Plain text password (will be hashed)
        email (str, optional): Email address
        
    Returns:
        bool: True if user created successfully, False otherwise
    """
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        cursor.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, hashed_password, email)
        )
        connection.commit()
        return True
        
    except Exception as e:
        print(f"Error creating user: {e}")
        return False
    finally:
        connection.close()


def verify_user(username, password):
    """
    Verify user credentials for login.
    
    Args:
        username (str): Username to verify
        password (str): Plain text password to check
        
    Returns:
        dict: User data if verified, None otherwise
    """
    connection = get_db_connection()
    if not connection:
        return None
    
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        
        if row and check_password_hash(row['password'], password):
            return dict(row)
        return None
        
    except Exception as e:
        print(f"Error verifying user: {e}")
        return None
    finally:
        connection.close()


def get_user_by_username(username):
    """
    Get user by username.
    
    Args:
        username (str): Username to look up
        
    Returns:
        dict: User data if found, None otherwise
    """
    connection = get_db_connection()
    if not connection:
        return None
    
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT id, username, email FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return dict(row) if row else None
        
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None
    finally:
        connection.close()


def get_all_users():
    """
    Get all users from the database.
    
    Returns:
        list: List of user dictionaries
    """
    connection = get_db_connection()
    if not connection:
        return []
    
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT id, username, email FROM users ORDER BY id")
        rows = cursor.fetchall()
        return [dict(row) for row in rows] if rows else []
        
    except Exception as e:
        print(f"Error fetching users: {e}")
        return []
    finally:
        connection.close()


def user_exists(username):
    """
    Check if a username already exists in the database.
    
    Args:
        username (str): Username to check
        
    Returns:
        bool: True if user exists, False otherwise
    """
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        return cursor.fetchone() is not None
        
    except Exception as e:
        print(f"Error checking user: {e}")
        return False
    finally:
        connection.close()


def log_attack(ip_address, attack_type, status, confidence, source_port=None, 
               dest_port=None, protocol=None, packet_size=None, details=None):
    """
    Log a detected attack to the database.
    
    Args:
        ip_address (str): Source IP address
        attack_type (str): Type of attack detected
        status (str): Status of the detection (detected/blocked/allowed)
        confidence (float): Confidence score of the detection (0-1)
        source_port (int, optional): Source port number
        dest_port (int, optional): Destination port number
        protocol (str, optional): Network protocol
        packet_size (int, optional): Size of the packet
        details (str, optional): Additional details
        
    Returns:
        int: Log ID if successful, None otherwise
    """
    connection = get_db_connection()
    if not connection:
        return None
    
    try:
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO logs (ip_address, attack_type, status, confidence, 
                            source_port, dest_port, protocol, packet_size, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip_address, attack_type, status, confidence, source_port, 
              dest_port, protocol, packet_size, details))
        
        log_id = cursor.lastrowid
        connection.commit()
        connection.close()
        
        # Update daily statistics
        update_statistics(attack_type)
        
        # Create alert for attacks
        if attack_type != 'Normal':
            create_alert(log_id, attack_type, ip_address, confidence)
        
        return log_id
        
    except Exception as e:
        print(f"Error logging attack: {e}")
        return None
    finally:
        if connection:
            connection.close()


def create_alert(log_id, attack_type, ip_address, confidence):
    """
    Create an alert for a detected attack.
    
    Args:
        log_id (int): ID of the related log entry
        attack_type (str): Type of attack
        ip_address (str): Source IP address
        confidence (float): Detection confidence
    """
    connection = get_db_connection()
    if not connection:
        return
    
    try:
        cursor = connection.cursor()
        
        # Determine severity based on attack type and confidence
        if attack_type in ['DoS', 'Botnet'] or confidence > 0.95:
            severity = 'critical'
        elif attack_type in ['BruteForce', 'WebAttack'] or confidence > 0.85:
            severity = 'high'
        elif attack_type == 'PortScan' or confidence > 0.7:
            severity = 'medium'
        else:
            severity = 'low'
        
        message = f"{attack_type} attack detected from {ip_address} with {confidence*100:.1f}% confidence"
        
        cursor.execute("""
            INSERT INTO alerts (log_id, severity, message)
            VALUES (?, ?, ?)
        """, (log_id, severity, message))
        
        connection.commit()
        
    except Exception as e:
        print(f"Error creating alert: {e}")
    finally:
        connection.close()


def update_statistics(attack_type):
    """
    Update daily statistics for dashboard metrics.
    
    Args:
        attack_type (str): Type of traffic/attack to increment
    """
    connection = get_db_connection()
    if not connection:
        return
    
    try:
        cursor = connection.cursor()
        today = datetime.now().date().isoformat()
        
        # Check if entry exists for today
        cursor.execute("SELECT id FROM statistics WHERE date = ?", (today,))
        exists = cursor.fetchone()
        
        if exists:
            cursor.execute("""
                UPDATE statistics SET total_packets = total_packets + 1 WHERE date = ?
            """, (today,))
        else:
            cursor.execute("""
                INSERT INTO statistics (date, total_packets) VALUES (?, 1)
            """, (today,))
        
        # Update specific attack type counter
        column_map = {
            'Normal': 'normal_count',
            'DoS': 'dos_count',
            'BruteForce': 'bruteforce_count',
            'Botnet': 'botnet_count',
            'PortScan': 'portscan_count',
            'WebAttack': 'webattack_count'
        }
        
        if attack_type in column_map:
            column = column_map[attack_type]
            cursor.execute(f"""
                UPDATE statistics SET {column} = {column} + 1 
                WHERE date = ?
            """, (today,))
        
        connection.commit()
        
    except Exception as e:
        print(f"Error updating statistics: {e}")
    finally:
        connection.close()


def get_logs(limit=100, attack_type=None):
    """
    Retrieve attack logs from the database.
    
    Args:
        limit (int): Maximum number of logs to retrieve
        attack_type (str, optional): Filter by attack type
        
    Returns:
        list: List of log dictionaries
    """
    connection = get_db_connection()
    if not connection:
        return []
    
    try:
        cursor = connection.cursor()
        
        if attack_type:
            cursor.execute("""
                SELECT * FROM logs WHERE attack_type = ? 
                ORDER BY date DESC LIMIT ?
            """, (attack_type, limit))
        else:
            cursor.execute("""
                SELECT * FROM logs ORDER BY date DESC LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows] if rows else []
        
    except Exception as e:
        print(f"Error retrieving logs: {e}")
        return []
    finally:
        connection.close()


def get_alerts(limit=50, unread_only=False):
    """
    Retrieve alerts from the database.
    
    Args:
        limit (int): Maximum number of alerts to retrieve
        unread_only (bool): Only return unread alerts
        
    Returns:
        list: List of alert dictionaries
    """
    connection = get_db_connection()
    if not connection:
        return []
    
    try:
        cursor = connection.cursor()
        
        if unread_only:
            cursor.execute("""
                SELECT * FROM alerts WHERE is_read = 0 
                ORDER BY created_at DESC LIMIT ?
            """, (limit,))
        else:
            cursor.execute("""
                SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows] if rows else []
        
    except Exception as e:
        print(f"Error retrieving alerts: {e}")
        return []
    finally:
        connection.close()


def mark_alert_read(alert_id):
    """Mark an alert as read."""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        cursor.execute("UPDATE alerts SET is_read = 1 WHERE id = ?", (alert_id,))
        connection.commit()
        return True
        
    except Exception as e:
        print(f"Error marking alert as read: {e}")
        return False
    finally:
        connection.close()


def get_statistics():
    """
    Get aggregated statistics for dashboard.
    
    Returns:
        dict: Statistics data
    """
    connection = get_db_connection()
    if not connection:
        return {}
    
    try:
        cursor = connection.cursor()
        
        # Get total counts
        cursor.execute("""
            SELECT 
                SUM(total_packets) as total_packets,
                SUM(normal_count) as normal_count,
                SUM(dos_count) as dos_count,
                SUM(bruteforce_count) as bruteforce_count,
                SUM(botnet_count) as botnet_count,
                SUM(portscan_count) as portscan_count,
                SUM(webattack_count) as webattack_count
            FROM statistics
        """)
        row = cursor.fetchone()
        totals = dict(row) if row else {}
        
        # Get last 7 days data for charts
        cursor.execute("""
            SELECT * FROM statistics 
            ORDER BY date DESC LIMIT 7
        """)
        rows = cursor.fetchall()
        daily_stats = [dict(row) for row in rows] if rows else []
        
        # Get unread alerts count
        cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE is_read = 0")
        row = cursor.fetchone()
        unread_alerts = row['count'] if row else 0
        
        return {
            'totals': totals,
            'daily_stats': daily_stats,
            'unread_alerts': unread_alerts
        }
        
    except Exception as e:
        print(f"Error getting statistics: {e}")
        return {}
    finally:
        connection.close()


def get_attack_distribution():
    """
    Get attack type distribution for pie chart.
    
    Returns:
        dict: Attack distribution data
    """
    connection = get_db_connection()
    if not connection:
        return {}
    
    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT attack_type, COUNT(*) as count 
            FROM logs 
            GROUP BY attack_type
        """)
        results = cursor.fetchall()
        
        distribution = {row['attack_type']: row['count'] for row in results}
        return distribution
        
    except Exception as e:
        print(f"Error getting attack distribution: {e}")
        return {}
    finally:
        connection.close()


def get_traffic_over_time(days=7):
    """
    Get traffic data over time for line chart.
    
    Args:
        days (int): Number of days to retrieve
        
    Returns:
        list: Daily traffic data
    """
    connection = get_db_connection()
    if not connection:
        return []
    
    try:
        cursor = connection.cursor()
        cutoff_date = (datetime.now() - timedelta(days=days)).date().isoformat()
        
        cursor.execute("""
            SELECT DATE(date) as day, 
                   COUNT(*) as total,
                   SUM(CASE WHEN attack_type = 'Normal' THEN 1 ELSE 0 END) as normal,
                   SUM(CASE WHEN attack_type != 'Normal' THEN 1 ELSE 0 END) as attacks
            FROM logs 
            WHERE date >= ?
            GROUP BY DATE(date)
            ORDER BY day
        """, (cutoff_date,))
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows] if rows else []
        
    except Exception as e:
        print(f"Error getting traffic over time: {e}")
        return []
    finally:
        connection.close()


def clear_logs():
    """Clear all logs from the database."""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM alerts")
        cursor.execute("DELETE FROM logs")
        cursor.execute("DELETE FROM statistics")
        connection.commit()
        return True
        
    except Exception as e:
        print(f"Error clearing logs: {e}")
        return False
    finally:
        connection.close()


# =====================================
# WEBSITE MONITORING SYSTEM
# =====================================

def init_monitoring_tables():
    """
    Initialize tables for website monitoring, failed login tracking, and IP blocking.
    """
    connection = None
    cursor = None
    try:
        connection = sqlite3.connect(DB_PATH)
        cursor = connection.cursor()
        
        # Create monitored_websites table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS monitored_websites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                name TEXT,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_checked TIMESTAMP
            )
        """)
        
        # Create failed_login_attempts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS failed_login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website_id INTEGER,
                ip_address TEXT NOT NULL,
                latitude REAL,
                longitude REAL,
                country TEXT,
                city TEXT,
                region TEXT,
                isp TEXT,
                device_type TEXT,
                browser TEXT,
                os TEXT,
                user_agent TEXT,
                attempt_count INTEGER DEFAULT 1,
                first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_blocked INTEGER DEFAULT 0,
                FOREIGN KEY (website_id) REFERENCES monitored_websites(id) ON DELETE CASCADE
            )
        """)
        
        # Create blocked_ips table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT,
                website_id INTEGER,
                latitude REAL,
                longitude REAL,
                country TEXT,
                city TEXT,
                blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                blocked_until TIMESTAMP,
                is_permanent INTEGER DEFAULT 0,
                FOREIGN KEY (website_id) REFERENCES monitored_websites(id) ON DELETE SET NULL
            )
        """)
        
        # Create realtime_activities table for live monitoring
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS realtime_activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website_id INTEGER,
                activity_type TEXT NOT NULL,
                ip_address TEXT,
                details TEXT,
                severity TEXT DEFAULT 'info',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (website_id) REFERENCES monitored_websites(id) ON DELETE CASCADE
            )
        """)
        
        # Create notifications table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                notification_type TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT,
                ip_address TEXT,
                website_id INTEGER,
                is_read INTEGER DEFAULT 0,
                priority TEXT DEFAULT 'medium',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (website_id) REFERENCES monitored_websites(id) ON DELETE SET NULL
            )
        """)
        
        connection.commit()
        print("[OK] Website monitoring tables initialized!")
        
    except Exception as e:
        print(f"Error initializing monitoring tables: {e}")
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def add_monitored_website(url, name=None):
    """Add a website to monitoring list."""
    connection = get_db_connection()
    if not connection:
        return None
    
    try:
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO monitored_websites (url, name) VALUES (?, ?)",
            (url, name or url)
        )
        connection.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        return -1  # Already exists
    except Exception as e:
        print(f"Error adding monitored website: {e}")
        return None
    finally:
        connection.close()


def remove_monitored_website(website_id):
    """Remove a website from monitoring list."""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM monitored_websites WHERE id = ?", (website_id,))
        connection.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Error removing monitored website: {e}")
        return False
    finally:
        connection.close()


def get_monitored_websites():
    """Get all monitored websites."""
    connection = get_db_connection()
    if not connection:
        return []
    
    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT mw.*, 
                   COUNT(DISTINCT fla.ip_address) as unique_attackers,
                   SUM(fla.attempt_count) as total_attempts
            FROM monitored_websites mw
            LEFT JOIN failed_login_attempts fla ON mw.id = fla.website_id
            GROUP BY mw.id
            ORDER BY mw.created_at DESC
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows] if rows else []
    except Exception as e:
        print(f"Error getting monitored websites: {e}")
        return []
    finally:
        connection.close()


def record_failed_login(website_id, ip_address, geo_data=None, device_data=None):
    """
    Record a failed login attempt. If 5+ attempts, auto-create notification.
    Returns the attempt count for this IP.
    """
    connection = get_db_connection()
    if not connection:
        return 0
    
    try:
        cursor = connection.cursor()
        geo = geo_data or {}
        device = device_data or {}
        
        # Check if this IP already has attempts for this website
        cursor.execute("""
            SELECT id, attempt_count FROM failed_login_attempts 
            WHERE website_id = ? AND ip_address = ?
        """, (website_id, ip_address))
        existing = cursor.fetchone()
        
        if existing:
            new_count = existing['attempt_count'] + 1
            cursor.execute("""
                UPDATE failed_login_attempts 
                SET attempt_count = ?, last_attempt = CURRENT_TIMESTAMP,
                    latitude = COALESCE(?, latitude),
                    longitude = COALESCE(?, longitude),
                    country = COALESCE(?, country),
                    city = COALESCE(?, city),
                    region = COALESCE(?, region),
                    isp = COALESCE(?, isp),
                    device_type = COALESCE(?, device_type),
                    browser = COALESCE(?, browser),
                    os = COALESCE(?, os),
                    user_agent = COALESCE(?, user_agent)
                WHERE id = ?
            """, (
                new_count,
                geo.get('latitude'), geo.get('longitude'),
                geo.get('country'), geo.get('city'),
                geo.get('region'), geo.get('isp'),
                device.get('device_type'), device.get('browser'),
                device.get('os'), device.get('user_agent'),
                existing['id']
            ))
            attempt_count = new_count
        else:
            cursor.execute("""
                INSERT INTO failed_login_attempts 
                (website_id, ip_address, latitude, longitude, country, city, region, isp,
                 device_type, browser, os, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                website_id, ip_address,
                geo.get('latitude'), geo.get('longitude'),
                geo.get('country'), geo.get('city'),
                geo.get('region'), geo.get('isp'),
                device.get('device_type'), device.get('browser'),
                device.get('os'), device.get('user_agent')
            ))
            attempt_count = 1
        
        # Create notification if threshold reached
        if attempt_count >= 5:
            cursor.execute("""
                SELECT url FROM monitored_websites WHERE id = ?
            """, (website_id,))
            website = cursor.fetchone()
            website_name = website['url'] if website else 'Unknown'
            
            cursor.execute("""
                INSERT INTO security_notifications 
                (notification_type, title, message, ip_address, website_id, priority)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                'brute_force',
                f'⚠️ Brute Force Attack Detected',
                f'IP {ip_address} has attempted {attempt_count} failed logins on {website_name}. '
                f'Location: {geo.get("city", "Unknown")}, {geo.get("country", "Unknown")}',
                ip_address,
                website_id,
                'high' if attempt_count >= 10 else 'medium'
            ))
        
        connection.commit()
        return attempt_count
        
    except Exception as e:
        print(f"Error recording failed login: {e}")
        return 0
    finally:
        connection.close()


def get_failed_login_attempts(website_id=None, limit=100):
    """Get failed login attempts, optionally filtered by website."""
    connection = get_db_connection()
    if not connection:
        return []
    
    try:
        cursor = connection.cursor()
        if website_id:
            cursor.execute("""
                SELECT fla.*, mw.url as website_url
                FROM failed_login_attempts fla
                LEFT JOIN monitored_websites mw ON fla.website_id = mw.id
                WHERE fla.website_id = ?
                ORDER BY fla.last_attempt DESC
                LIMIT ?
            """, (website_id, limit))
        else:
            cursor.execute("""
                SELECT fla.*, mw.url as website_url
                FROM failed_login_attempts fla
                LEFT JOIN monitored_websites mw ON fla.website_id = mw.id
                ORDER BY fla.last_attempt DESC
                LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows] if rows else []
    except Exception as e:
        print(f"Error getting failed login attempts: {e}")
        return []
    finally:
        connection.close()


def block_ip_address(ip_address, reason=None, website_id=None, geo_data=None, is_permanent=False):
    """Block an IP address."""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        geo = geo_data or {}
        
        cursor.execute("""
            INSERT OR REPLACE INTO blocked_ips 
            (ip_address, reason, website_id, latitude, longitude, country, city, is_permanent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip_address, reason, website_id,
            geo.get('latitude'), geo.get('longitude'),
            geo.get('country'), geo.get('city'),
            1 if is_permanent else 0
        ))
        
        # Mark as blocked in failed_login_attempts
        cursor.execute("""
            UPDATE failed_login_attempts SET is_blocked = 1 WHERE ip_address = ?
        """, (ip_address,))
        
        # Create notification
        cursor.execute("""
            INSERT INTO security_notifications 
            (notification_type, title, message, ip_address, website_id, priority)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            'ip_blocked',
            '🛡️ IP Address Blocked',
            f'IP {ip_address} has been blocked. Reason: {reason or "Manual block"}',
            ip_address,
            website_id,
            'info'
        ))
        
        connection.commit()
        return True
    except Exception as e:
        print(f"Error blocking IP: {e}")
        return False
    finally:
        connection.close()


def unblock_ip_address(ip_address):
    """Unblock an IP address."""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
        cursor.execute("""
            UPDATE failed_login_attempts SET is_blocked = 0 WHERE ip_address = ?
        """, (ip_address,))
        connection.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Error unblocking IP: {e}")
        return False
    finally:
        connection.close()


def get_blocked_ips():
    """Get all blocked IPs."""
    connection = get_db_connection()
    if not connection:
        return []
    
    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT bi.*, mw.url as website_url
            FROM blocked_ips bi
            LEFT JOIN monitored_websites mw ON bi.website_id = mw.id
            ORDER BY bi.blocked_at DESC
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows] if rows else []
    except Exception as e:
        print(f"Error getting blocked IPs: {e}")
        return []
    finally:
        connection.close()


def is_ip_blocked(ip_address):
    """Check if an IP is blocked."""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT id FROM blocked_ips WHERE ip_address = ?", (ip_address,))
        return cursor.fetchone() is not None
    except Exception as e:
        print(f"Error checking blocked IP: {e}")
        return False
    finally:
        connection.close()


def log_realtime_activity(website_id, activity_type, ip_address=None, details=None, severity='info'):
    """Log a realtime activity for a monitored website."""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO realtime_activities 
            (website_id, activity_type, ip_address, details, severity)
            VALUES (?, ?, ?, ?, ?)
        """, (website_id, activity_type, ip_address, details, severity))
        connection.commit()
        return True
    except Exception as e:
        print(f"Error logging realtime activity: {e}")
        return False
    finally:
        connection.close()


def get_realtime_activities(website_id=None, limit=50):
    """Get realtime activities."""
    connection = get_db_connection()
    if not connection:
        return []
    
    try:
        cursor = connection.cursor()
        if website_id:
            cursor.execute("""
                SELECT ra.*, mw.url as website_url
                FROM realtime_activities ra
                LEFT JOIN monitored_websites mw ON ra.website_id = mw.id
                WHERE ra.website_id = ?
                ORDER BY ra.timestamp DESC
                LIMIT ?
            """, (website_id, limit))
        else:
            cursor.execute("""
                SELECT ra.*, mw.url as website_url
                FROM realtime_activities ra
                LEFT JOIN monitored_websites mw ON ra.website_id = mw.id
                ORDER BY ra.timestamp DESC
                LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows] if rows else []
    except Exception as e:
        print(f"Error getting realtime activities: {e}")
        return []
    finally:
        connection.close()


def add_security_notification(notification_type, title, message, severity='info', ip_address=None, website_id=None):
    """Add a security notification."""
    connection = get_db_connection()
    if not connection:
        return None
    
    try:
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO security_notifications 
            (notification_type, title, message, ip_address, website_id, priority)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (notification_type, title, message, ip_address, website_id, severity))
        
        connection.commit()
        return cursor.lastrowid
    except Exception as e:
        print(f"Error adding security notification: {e}")
        return None
    finally:
        connection.close()


def add_realtime_activity(website_id, activity_type, ip_address=None, details=None, severity='info'):
    """Add a realtime activity entry (alias for log_realtime_activity)."""
    return log_realtime_activity(website_id, activity_type, ip_address, details, severity)


def get_security_notifications(unread_only=False, limit=50):
    """Get security notifications."""
    connection = get_db_connection()
    if not connection:
        return []
    
    try:
        cursor = connection.cursor()
        if unread_only:
            cursor.execute("""
                SELECT sn.*, mw.url as website_url
                FROM security_notifications sn
                LEFT JOIN monitored_websites mw ON sn.website_id = mw.id
                WHERE sn.is_read = 0
                ORDER BY sn.created_at DESC
                LIMIT ?
            """, (limit,))
        else:
            cursor.execute("""
                SELECT sn.*, mw.url as website_url
                FROM security_notifications sn
                LEFT JOIN monitored_websites mw ON sn.website_id = mw.id
                ORDER BY sn.created_at DESC
                LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows] if rows else []
    except Exception as e:
        print(f"Error getting notifications: {e}")
        return []
    finally:
        connection.close()


def mark_notification_read(notification_id):
    """Mark a notification as read."""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        cursor.execute("""
            UPDATE security_notifications SET is_read = 1 WHERE id = ?
        """, (notification_id,))
        connection.commit()
        return True
    except Exception as e:
        print(f"Error marking notification read: {e}")
        return False
    finally:
        connection.close()


def get_attacker_locations():
    """Get all attacker locations for map display."""
    connection = get_db_connection()
    if not connection:
        return []
    
    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT ip_address, latitude, longitude, country, city, 
                   SUM(attempt_count) as total_attempts, 
                   MAX(is_blocked) as is_blocked,
                   MAX(last_attempt) as last_seen
            FROM failed_login_attempts
            WHERE latitude IS NOT NULL AND longitude IS NOT NULL
            GROUP BY ip_address
            ORDER BY total_attempts DESC
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows] if rows else []
    except Exception as e:
        print(f"Error getting attacker locations: {e}")
        return []
    finally:
        connection.close()


if __name__ == "__main__":
    # Initialize database when run directly
    print("Initializing NIDS Database...")
    init_database()
    init_monitoring_tables()
