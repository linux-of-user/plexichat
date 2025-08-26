# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import ipaddress
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
import time

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

logger = logging.getLogger(__name__)

class IPSecurityManager:
    """Advanced IP security and geolocation management system."""
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or str(Path("logs") / "ip_security.json")

        # IP lists
        self.whitelist: Set[str] = set()
        self.blacklist: Set[str] = set()
        self.temp_blacklist: Dict[str, datetime] = {}

        # Network ranges
        self.whitelist_networks: List[ipaddress.IPv4Network] = []
        self.blacklist_networks: List[ipaddress.IPv4Network] = []

        # Country/region restrictions
        self.allowed_countries: Set[str] = set()
        self.blocked_countries: Set[str] = set()

        # Rate limiting and monitoring
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.suspicious_ips: Dict[str, Dict] = {}

        # Configuration
        self.config = {
            'enable_whitelist': False,
            'enable_blacklist': True,
            'enable_geo_blocking': False,
            'enable_auto_blocking': True,
            'max_failed_attempts': 5,
            'auto_block_duration_minutes': 60,
            'suspicious_threshold': 10,
            'check_proxy_headers': True,
            'allow_private_networks': True,
            'log_all_requests': False
        }

        # GeoIP database
        self.geoip_db = None
        self._init_geoip()

        # Load configuration
        self._load_config()

        # Default safe networks (RFC 1918 private networks)
        self._add_default_safe_networks()

    def _init_geoip(self):
        """Initialize GeoIP database."""
        if not GEOIP_AVAILABLE:
            logger.warning("GeoIP2 not available. Geographic blocking disabled.")
            return

        try:
            # Try to find GeoIP database
            possible_paths = [
                '/usr/share/GeoIP/GeoLite2-Country.mmdb',
                '/opt/GeoIP/GeoLite2-Country.mmdb',
                './GeoLite2-Country.mmdb',
                str(Path("logs") / 'GeoLite2-Country.mmdb')
            ]

            for path in possible_paths:
                if Path(path).exists():
                    self.geoip_db = geoip2.database.Reader(path)
                    logger.info("GeoIP database loaded from %s", path)
                    break

            if not self.geoip_db:
                logger.warning("GeoIP database not found. Geographic blocking disabled.")

        except Exception as e:
            logger.warning("Failed to initialize GeoIP database: %s", e)

    def _add_default_safe_networks(self):
        """Add default safe networks (private IP ranges)."""
        if self.config.get('allow_private_networks', True):
            safe_networks = [
                '127.0.0.0/8',    # Loopback
                '10.0.0.0/8',     # Private Class A
                '172.16.0.0/12',  # Private Class B
                '192.168.0.0/16', # Private Class C
                '169.254.0.0/16', # Link-local
            ]

            for network in safe_networks:
                try:
                    self.whitelist_networks.append(ipaddress.ip_network(network))
                except Exception as e:
                    logger.warning("Failed to add safe network %s: %s", network, e)

    def _load_config(self):
        """Load IP security configuration from file."""
        try:
            config_path = Path(self.config_file)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    data = json.load(f)

                # Load configuration
                self.config.update(data.get('config', {}))

                # Load IP lists
                self.whitelist = set(data.get('whitelist', []))
                self.blacklist = set(data.get('blacklist', []))

                # Load network ranges
                for network_str in data.get('whitelist_networks', []):
                    try:
                        self.whitelist_networks.append(ipaddress.ip_network(network_str))
                    except Exception as e:
                        logger.warning("Invalid whitelist network %s: %s", network_str, e)

                for network_str in data.get('blacklist_networks', []):
                    try:
                        self.blacklist_networks.append(ipaddress.ip_network(network_str))
                    except Exception as e:
                        logger.warning("Invalid blacklist network %s: %s", network_str, e)

                # Load country restrictions
                self.allowed_countries = set(data.get('allowed_countries', []))
                self.blocked_countries = set(data.get('blocked_countries', []))

                # Load temporary blacklist with datetime conversion
                temp_blacklist_data = data.get('temp_blacklist', {})
                for ip, timestamp_str in temp_blacklist_data.items():
                    try:
                        self.temp_blacklist[ip] = datetime.fromisoformat(timestamp_str)
                    except Exception as e:
                        logger.warning("Invalid temp blacklist timestamp for %s: %s", ip, e)

                logger.info("IP security configuration loaded from %s", self.config_file)

        except Exception as e:
            logger.warning("Failed to load IP security config: %s", e)

    def _save_config(self):
        """Save IP security configuration to file."""
        try:
            # Prepare data for serialization
            data = {
                'config': self.config,
                'whitelist': list(self.whitelist),
                'blacklist': list(self.blacklist),
                'whitelist_networks': [str(net) for net in self.whitelist_networks if not self._is_default_safe_network(net)],
                'blacklist_networks': [str(net) for net in self.blacklist_networks],
                'allowed_countries': list(self.allowed_countries),
                'blocked_countries': list(self.blocked_countries),
                'temp_blacklist': {
                    ip: timestamp.isoformat()
                    for ip, timestamp in self.temp_blacklist.items()
                }
            }

            config_path = Path(self.config_file)
            config_path.parent.mkdir(parents=True, exist_ok=True)

            with open(config_path, 'w') as f:
                json.dump(data, f, indent=2)

            logger.debug("IP security configuration saved to %s", self.config_file)

        except Exception as e:
            logger.error("Failed to save IP security config: %s", e)

    def _is_default_safe_network(self, network: ipaddress.IPv4Network) -> bool:
        """Check if network is a default safe network."""
        safe_networks = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16']
        return str(network) in safe_networks

    def get_client_ip(self, request) -> str:
        """Extract client IP from request with proxy header support."""
        if self.config.get('check_proxy_headers', True):
            # Check proxy headers in order of preference
            proxy_headers = [
                'X-Forwarded-For',
                'X-Real-IP',
                'X-Client-IP',
                'CF-Connecting-IP',  # Cloudflare
                'True-Client-IP',    # Akamai
            ]

            for header in proxy_headers:
                ip_value = request.headers.get(header)
                if ip_value:
                    # X-Forwarded-For can contain multiple IPs
                    if header == 'X-Forwarded-For':
                        ip_value = ip_value.split(',')[0].strip()

                    # Validate IP
                    try:
                        ipaddress.ip_address(ip_value)
                        return ip_value
                    except ValueError:
                        continue

        # Fall back to direct connection IP
        return request.client.host if hasattr(request, 'client') else '127.0.0.1'

    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is allowed based on current security rules."""
        try:
            # Validate IP address
            ip_obj = ipaddress.ip_address(ip)

            # Check whitelist first
            if self.config.get('enable_whitelist', False):
                if ip in self.whitelist:
                    return True

                # Check whitelist networks
                for network in self.whitelist_networks:
                    if ip_obj in network:
                        return True

            # Check blacklist
            if self.config.get('enable_blacklist', True):
                if ip in self.blacklist:
                    logger.warning("Blocked IP %s (blacklisted)", ip)
                    return False

                # Check blacklist networks
                for network in self.blacklist_networks:
                    if ip_obj in network:
                        logger.warning("Blocked IP %s (blacklisted network %s)", ip, network)
                        return False

            # Check temporary blacklist
            if ip in self.temp_blacklist:
                block_until = self.temp_blacklist[ip]
                if datetime.now() < block_until:
                    logger.warning("Blocked IP %s (temporarily blocked until %s)", ip, block_until)
                    return False
                else:
                    # Remove expired temporary block
                    del self.temp_blacklist[ip]

            # Check geographic restrictions
            if self.config.get('enable_geo_blocking', False) and self.geoip_db:
                country = self._get_ip_country(ip)
                if country:
                    if self.allowed_countries and country not in self.allowed_countries:
                        logger.warning("Blocked IP %s (country %s not allowed)", ip, country)
                        return False

                    if country in self.blocked_countries:
                        logger.warning("Blocked IP %s (country %s blocked)", ip, country)
                        return False

            return True

        except ValueError:
            logger.warning("Invalid IP address: %s", ip)
            return False
        except Exception as e:
            logger.error("Error checking IP %s: %s", ip, e)
            return False

    def _get_ip_country(self, ip: str) -> Optional[str]:
        """Get country code for IP address."""
        if not self.geoip_db:
            return None

        try:
            response = self.geoip_db.country(ip)
            return response.country.iso_code
        except Exception as e:
            logger.debug("Failed to get country for IP %s: %s", ip, e)
            return None

    def record_failed_attempt(self, ip: str):
        """Record a failed authentication attempt for an IP."""
        now = datetime.now()

        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []

        self.failed_attempts[ip].append(now)

        # Clean old attempts (keep last hour)
        cutoff = now - timedelta(hours=1)
        self.failed_attempts[ip] = [
            attempt for attempt in self.failed_attempts[ip]
            if attempt > cutoff
        ]

        # Check if IP should be auto-blocked
        max_attempts = self.config.get('max_failed_attempts', 5)
        if len(self.failed_attempts[ip]) >= max_attempts:
            self._auto_block_ip(ip)

        # Log suspicious activity
        if len(self.failed_attempts[ip]) >= self.config.get('suspicious_threshold', 10):
            self._mark_suspicious(ip)

    def _auto_block_ip(self, ip: str):
        """Automatically block an IP due to failed attempts."""
        if not self.config.get('enable_auto_blocking', True):
            return

        duration_minutes = self.config.get('auto_block_duration_minutes', 60)
        block_until = datetime.now() + timedelta(minutes=duration_minutes)

        self.temp_blacklist[ip] = block_until

        logger.warning("Auto-blocked IP %s until %s (failed attempts)", ip, block_until)

        # Save configuration
        self._save_config()

    def _mark_suspicious(self, ip: str):
        """Mark an IP as suspicious for monitoring."""
        if ip not in self.suspicious_ips:
            self.suspicious_ips[ip] = {
                'first_seen': datetime.now(),
                'failed_attempts': 0,
                'last_attempt': datetime.now()
            }

        self.suspicious_ips[ip]['failed_attempts'] += 1
        self.suspicious_ips[ip]['last_attempt'] = datetime.now()

        logger.warning("Marked IP %s as suspicious (%d failed attempts)",
                    ip, self.suspicious_ips[ip]['failed_attempts'])

    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist."""
        self.whitelist.add(ip)
        self._save_config()
        logger.info("Added IP %s to whitelist", ip)

    def add_to_blacklist(self, ip: str):
        """Add IP to blacklist."""
        self.blacklist.add(ip)
        self._save_config()
        logger.info("Added IP %s to blacklist", ip)

    def remove_from_whitelist(self, ip: str):
        """Remove IP from whitelist."""
        self.whitelist.discard(ip)
        self._save_config()
        logger.info("Removed IP %s from whitelist", ip)

    def remove_from_blacklist(self, ip: str):
        """Remove IP from blacklist."""
        self.blacklist.discard(ip)
        self._save_config()
        logger.info("Removed IP %s from blacklist", ip)

    def get_security_stats(self) -> Dict:
        """Get security statistics."""
        return {
            'whitelist_count': len(self.whitelist),
            'blacklist_count': len(self.blacklist),
            'temp_blacklist_count': len(self.temp_blacklist),
            'suspicious_ips_count': len(self.suspicious_ips),
            'failed_attempts_count': sum(len(attempts) for attempts in self.failed_attempts.values()),
            'whitelist_networks': [str(net) for net in self.whitelist_networks],
            'blacklist_networks': [str(net) for net in self.blacklist_networks],
            'allowed_countries': list(self.allowed_countries),
            'blocked_countries': list(self.blocked_countries)
        }

# Global instance
ip_security_manager = IPSecurityManager()

def is_ip_allowed(ip: str) -> bool:
    """Check if IP is allowed."""
    return ip_security_manager.is_ip_allowed(ip)
