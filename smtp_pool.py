import smtplib
import time
from typing import Dict, Optional, Tuple, List
from threading import Lock
import logging
import socket
from config import SMTP_CONFIG

class SMTPConnection:
    """Represents a single SMTP connection with metadata and health tracking"""

    def __init__(self, host: str, port: int = 25, timeout: int = SMTP_CONFIG['TIMEOUT']):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.connection: Optional[smtplib.SMTP] = None
        self.last_used: float = 0
        self.created_at: float = time.time()
        self.use_count: int = 0
        self.is_busy: bool = False
        self.error_count: int = 0
        self.last_error: Optional[str] = None

    def connect(self) -> bool:
        """
        Establish SMTP connection with retry logic

        Returns:
            bool: Whether connection was successful
        """
        for attempt in range(SMTP_CONFIG['RETRY_COUNT']):
            try:
                self.connection = smtplib.SMTP(timeout=self.timeout)
                self.connection.connect(self.host, self.port)
                # Try EHLO/HELO
                try:
                    self.connection.ehlo()
                except:
                    try:
                        self.connection.helo()
                    except:
                        pass
                self.last_used = time.time()
                self.error_count = 0
                self.last_error = None
                return True
            except Exception as e:
                self.last_error = str(e)
                self.error_count += 1
                if attempt < SMTP_CONFIG['RETRY_COUNT'] - 1:
                    time.sleep(SMTP_CONFIG['RETRY_DELAY'])
                continue
        return False

    def disconnect(self) -> None:
        """Safely close SMTP connection"""
        try:
            if self.connection:
                self.connection.quit()
        except:
            pass
        finally:
            self.connection = None

    def is_connected(self) -> bool:
        """
        Check if connection is still alive using NOOP

        Returns:
            bool: Whether connection is responsive
        """
        if not self.connection:
            return False
        try:
            status = self.connection.noop()[0]
            return status == 250
        except:
            return False

    def refresh_if_needed(self, max_age: int = SMTP_CONFIG['MAX_AGE']) -> bool:
        """
        Refresh connection if it's too old or unresponsive

        Args:
            max_age: Maximum age in seconds before refresh

        Returns:
            bool: Whether connection is now valid
        """
        if (time.time() - self.last_used > max_age) or not self.is_connected():
            self.disconnect()
            return self.connect()
        return True

class SMTPConnectionPool:
    """Manages a pool of SMTP connections with health monitoring"""

    def __init__(self, 
                 max_connections: int = SMTP_CONFIG['MAX_CONNECTIONS'],
                 connection_timeout: int = SMTP_CONFIG['CONNECTION_TIMEOUT'],
                 max_age: int = SMTP_CONFIG['MAX_AGE']):
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout
        self.max_age = max_age
        self.connections: Dict[str, List[SMTPConnection]] = {}
        self.lock = Lock()
        self.logger = logging.getLogger('smtp_pool')

    def _get_connection_key(self, host: str, port: int = 25) -> str:
        """Generate unique key for connection storage"""
        return f"{host}:{port}"

    def get_connection(self, host: str, port: int = 25) -> Optional[SMTPConnection]:
        """
        Get an available connection from the pool

        Args:
            host: SMTP host
            port: SMTP port

        Returns:
            SMTPConnection if available, None otherwise
        """
        key = self._get_connection_key(host, port)

        with self.lock:
            # Initialize connection list if needed
            if key not in self.connections:
                self.connections[key] = []

            # Try to find an available connection
            for conn in self.connections[key]:
                if not conn.is_busy:
                    if conn.refresh_if_needed(self.max_age):
                        conn.is_busy = True
                        conn.use_count += 1
                        conn.last_used = time.time()
                        return conn
                    else:
                        # Remove failed connection
                        conn.disconnect()
                        self.connections[key].remove(conn)

            # Create new connection if pool isn't full
            if len(self.connections[key]) < self.max_connections:
                conn = SMTPConnection(host, port, self.connection_timeout)
                if conn.connect():
                    conn.is_busy = True
                    self.connections[key].append(conn)
                    return conn
                else:
                    self.logger.warning(f"Failed to create new connection to {host}:{port}")

            self.logger.warning(f"No available connections for {host}:{port}")
            return None

    def release_connection(self, conn: SMTPConnection) -> None:
        """
        Release connection back to the pool

        Args:
            conn: Connection to release
        """
        with self.lock:
            conn.is_busy = False
            conn.last_used = time.time()

    def cleanup(self, force: bool = False) -> None:
        """
        Remove dead or old connections

        Args:
            force: Whether to remove all connections
        """
        with self.lock:
            for key in list(self.connections.keys()):
                for conn in self.connections[key][:]:
                    if force or time.time() - conn.last_used > self.max_age or not conn.is_connected():
                        conn.disconnect()
                        self.connections[key].remove(conn)

    def get_pool_stats(self) -> Dict:
        """
        Get current pool statistics

        Returns:
            Dict containing pool statistics
        """
        stats = {
            'total_connections': 0,
            'active_connections': 0,
            'connections_by_host': {},
            'error_rates': {}
        }

        with self.lock:
            for key, conns in self.connections.items():
                host_stats = {
                    'total': len(conns),
                    'active': sum(1 for c in conns if c.is_busy),
                    'errors': sum(c.error_count for c in conns)
                }
                stats['connections_by_host'][key] = host_stats
                stats['total_connections'] += host_stats['total']
                stats['active_connections'] += host_stats['active']
                if host_stats['total'] > 0:
                    stats['error_rates'][key] = host_stats['errors'] / host_stats['total']

        return stats

# Global connection pool instance
smtp_pool = SMTPConnectionPool()

class SMTPContext:
    """Context manager for SMTP connections"""

    def __init__(self, host: str, port: int = 25):
        self.host = host
        self.port = port
        self.connection = None

    def __enter__(self) -> Optional[SMTPConnection]:
        self.connection = smtp_pool.get_connection(self.host, self.port)
        return self.connection

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection:
            smtp_pool.release_connection(self.connection)

def verify_email_with_pool(email: str, mx_records: List[str]) -> Tuple[bool, str]:
    """
    Helper function to verify email using connection pool

    Args:
        email: Email address to verify
        mx_records: List of MX records to try

    Returns:
        Tuple containing:
        - bool: Whether verification was successful
        - str: Status message
    """
    for mx in mx_records[:2]:  # Try first two MX records
        try:
            with SMTPContext(mx) as conn:
                if not conn or not conn.connection:
                    continue

                # Try email verification
                try:
                    conn.connection.mail('')
                    code, message = conn.connection.rcpt(email)
                    if code == 250:
                        return True, "Email exists"
                    elif code == 550:
                        return False, "Mailbox does not exist"
                    elif code in [421, 450, 451, 452]:
                        return True, "Server temporarily unavailable"
                except smtplib.SMTPServerDisconnected:
                    continue
                except smtplib.SMTPResponseException as e:
                    if e.smtp_code in [421, 450, 451, 452]:
                        return True, "Server temporarily unavailable"
                    continue

        except Exception as e:
            logging.error(f"SMTP verification error for {mx}: {str(e)}")
            continue

    return False, "Could not verify email"