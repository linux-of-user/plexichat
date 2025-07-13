# app/utils/ip_security.py
"""
IP-based security system with whitelist/blacklist management,
geolocation blocking, and advanced access control.
"""

import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import geoip2.database
import geoip2.errors
from app.logger_config import logger, settings
from fastapi import Request


class IPSecurityManager:
    """Comprehensive IP-based security management."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or str(Path(settings.LOG_DIR) / "ip_security.json")
        
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
        try:
            # Try to find GeoIP database
            possible_paths = [
                '/usr/share/GeoIP/GeoLite2-Country.mmdb',
                '/opt/GeoIP/GeoLite2-Country.mmdb',
                './GeoLite2-Country.mmdb',
                str(Path(settings.LOG_DIR) / 'GeoLite2-Country.mmdb')
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
                    self.whitelist_networks.append(ipaddress.IPv4Network(network))
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
                        self.whitelist_networks.append(ipaddress.IPv4Network(network_str))
                    except Exception as e:
                        logger.warning("Invalid whitelist network %s: %s", network_str, e)
                
                for network_str in data.get('blacklist_networks', []):
                    try:
                        self.blacklist_networks.append(ipaddress.IPv4Network(network_str))
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
    
    def get_client_ip(self, request: Request) -> str:
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
        return request.client.host if request.client else "unknown"
    
    def is_ip_allowed(self, ip_str: str) -> Tuple[bool, str]:
        """
        Check if an IP address is allowed access.
        
        Returns:
            Tuple of (is_allowed, reason)
        """
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP address: {ip_str}"
        
        # Check temporary blacklist first
        if ip_str in self.temp_blacklist:
            expiry = self.temp_blacklist[ip_str]
            if datetime.now(timezone.utc) < expiry:
                return False, f"IP temporarily blocked until {expiry}"
            else:
                # Remove expired entry
                del self.temp_blacklist[ip_str]
                self._save_config()
        
        # Check permanent blacklist
        if self.config.get('enable_blacklist', True):
            if ip_str in self.blacklist:
                return False, "IP is permanently blacklisted"
            
            # Check blacklist networks
            for network in self.blacklist_networks:
                if ip in network:
                    return False, f"IP is in blacklisted network {network}"
        
        # Check whitelist (if enabled, only whitelisted IPs are allowed)
        if self.config.get('enable_whitelist', False):
            if ip_str not in self.whitelist:
                # Check whitelist networks
                in_whitelist_network = False
                for network in self.whitelist_networks:
                    if ip in network:
                        in_whitelist_network = True
                        break
                
                if not in_whitelist_network:
                    return False, "IP not in whitelist"
        
        # Check geographic restrictions
        if self.config.get('enable_geo_blocking', False) and self.geoip_db:
            country_allowed, geo_reason = self._check_geographic_restrictions(ip_str)
            if not country_allowed:
                return False, geo_reason
        
        # Check for suspicious activity
        if self._is_suspicious_ip(ip_str):
            return False, "IP flagged for suspicious activity"
        
        return True, "Access allowed"
    
    def _check_geographic_restrictions(self, ip_str: str) -> Tuple[bool, str]:
        """Check geographic restrictions for an IP."""
        try:
            response = self.geoip_db.country(ip_str)
            country_code = response.country.iso_code
            
            # Check blocked countries
            if country_code in self.blocked_countries:
                return False, f"Access blocked from country: {country_code}"
            
            # Check allowed countries (if specified)
            if self.allowed_countries and country_code not in self.allowed_countries:
                return False, f"Access not allowed from country: {country_code}"
            
            return True, "Geographic check passed"
            
        except geoip2.errors.AddressNotFoundError:
            # IP not in database (likely private)
            return True, "IP not in geographic database"
        except Exception as e:
            logger.warning("Geographic check failed for %s: %s", ip_str, e)
            return True, "Geographic check error"
    
    def _is_suspicious_ip(self, ip_str: str) -> bool:
        """Check if IP has suspicious activity patterns."""
        if not self.config.get('enable_auto_blocking', True):
            return False
        
        # Check failed attempts
        failed_count = len(self.failed_attempts.get(ip_str, []))
        if failed_count >= self.config.get('max_failed_attempts', 5):
            return True
        
        # Check if IP is marked as suspicious
        if ip_str in self.suspicious_ips:
            suspicious_score = self.suspicious_ips[ip_str].get('score', 0)
            threshold = self.config.get('suspicious_threshold', 10)
            return suspicious_score >= threshold
        
        return False
    
    def record_failed_attempt(self, ip_str: str, reason: str = "authentication_failure"):
        """Record a failed attempt from an IP."""
        current_time = datetime.now(timezone.utc)
        
        # Add to failed attempts
        if ip_str not in self.failed_attempts:
            self.failed_attempts[ip_str] = []
        
        self.failed_attempts[ip_str].append(current_time)
        
        # Clean old attempts (older than 1 hour)
        cutoff_time = current_time - timedelta(hours=1)
        self.failed_attempts[ip_str] = [
            attempt for attempt in self.failed_attempts[ip_str]
            if attempt > cutoff_time
        ]
        
        # Check if IP should be auto-blocked
        failed_count = len(self.failed_attempts[ip_str])
        max_attempts = self.config.get('max_failed_attempts', 5)
        
        if failed_count >= max_attempts and self.config.get('enable_auto_blocking', True):
            self.add_to_temp_blacklist(
                ip_str, 
                self.config.get('auto_block_duration_minutes', 60),
                f"Auto-blocked after {failed_count} failed attempts"
            )
        
        # Update suspicious score
        self._update_suspicious_score(ip_str, reason)
        
        logger.warning("Failed attempt from %s: %s (total: %d)", ip_str, reason, failed_count)
    
    def _update_suspicious_score(self, ip_str: str, reason: str):
        """Update suspicious activity score for an IP."""
        if ip_str not in self.suspicious_ips:
            self.suspicious_ips[ip_str] = {
                'score': 0,
                'reasons': [],
                'first_seen': datetime.now(timezone.utc).isoformat(),
                'last_activity': datetime.now(timezone.utc).isoformat()
            }
        
        # Score weights for different reasons
        score_weights = {
            'authentication_failure': 1,
            'rate_limit_exceeded': 2,
            'invalid_request': 1,
            'sql_injection_attempt': 5,
            'xss_attempt': 5,
            'path_traversal': 3,
            'brute_force': 3
        }
        
        score_increase = score_weights.get(reason, 1)
        self.suspicious_ips[ip_str]['score'] += score_increase
        self.suspicious_ips[ip_str]['reasons'].append({
            'reason': reason,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'score': score_increase
        })
        self.suspicious_ips[ip_str]['last_activity'] = datetime.now(timezone.utc).isoformat()
        
        # Keep only recent reasons (last 100)
        if len(self.suspicious_ips[ip_str]['reasons']) > 100:
            self.suspicious_ips[ip_str]['reasons'] = self.suspicious_ips[ip_str]['reasons'][-100:]
    
    def add_to_whitelist(self, ip_or_network: str, description: str = ""):
        """Add IP or network to whitelist."""
        try:
            # Try to parse as network first
            if '/' in ip_or_network:
                network = ipaddress.IPv4Network(ip_or_network)
                self.whitelist_networks.append(network)
                logger.info("Added network %s to whitelist: %s", ip_or_network, description)
            else:
                # Validate as IP
                ipaddress.ip_address(ip_or_network)
                self.whitelist.add(ip_or_network)
                logger.info("Added IP %s to whitelist: %s", ip_or_network, description)
            
            self._save_config()
            
        except ValueError as e:
            raise ValueError(f"Invalid IP or network format: {e}")
    
    def add_to_blacklist(self, ip_or_network: str, description: str = ""):
        """Add IP or network to permanent blacklist."""
        try:
            # Try to parse as network first
            if '/' in ip_or_network:
                network = ipaddress.IPv4Network(ip_or_network)
                self.blacklist_networks.append(network)
                logger.info("Added network %s to blacklist: %s", ip_or_network, description)
            else:
                # Validate as IP
                ipaddress.ip_address(ip_or_network)
                self.blacklist.add(ip_or_network)
                logger.info("Added IP %s to blacklist: %s", ip_or_network, description)
            
            self._save_config()
            
        except ValueError as e:
            raise ValueError(f"Invalid IP or network format: {e}")
    
    def add_to_temp_blacklist(self, ip_str: str, duration_minutes: int, reason: str = ""):
        """Add IP to temporary blacklist."""
        try:
            ipaddress.ip_address(ip_str)
            expiry = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
            self.temp_blacklist[ip_str] = expiry
            
            logger.warning("Added IP %s to temporary blacklist until %s: %s", 
                         ip_str, expiry, reason)
            
            self._save_config()
            
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {e}")
    
    def remove_from_whitelist(self, ip_or_network: str):
        """Remove IP or network from whitelist."""
        removed = False
        
        if ip_or_network in self.whitelist:
            self.whitelist.remove(ip_or_network)
            removed = True
        
        # Check networks
        for network in self.whitelist_networks[:]:
            if str(network) == ip_or_network:
                self.whitelist_networks.remove(network)
                removed = True
        
        if removed:
            self._save_config()
            logger.info("Removed %s from whitelist", ip_or_network)
        
        return removed
    
    def remove_from_blacklist(self, ip_or_network: str):
        """Remove IP or network from blacklist."""
        removed = False
        
        if ip_or_network in self.blacklist:
            self.blacklist.remove(ip_or_network)
            removed = True
        
        if ip_or_network in self.temp_blacklist:
            del self.temp_blacklist[ip_or_network]
            removed = True
        
        # Check networks
        for network in self.blacklist_networks[:]:
            if str(network) == ip_or_network:
                self.blacklist_networks.remove(network)
                removed = True
        
        if removed:
            self._save_config()
            logger.info("Removed %s from blacklist", ip_or_network)
        
        return removed
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics."""
        current_time = datetime.now(timezone.utc)
        
        # Count active temporary blocks
        active_temp_blocks = sum(
            1 for expiry in self.temp_blacklist.values()
            if expiry > current_time
        )
        
        # Count recent failed attempts (last hour)
        cutoff_time = current_time - timedelta(hours=1)
        recent_failed_attempts = sum(
            len([attempt for attempt in attempts if attempt > cutoff_time])
            for attempts in self.failed_attempts.values()
        )
        
        return {
            'whitelist_ips': len(self.whitelist),
            'whitelist_networks': len([net for net in self.whitelist_networks if not self._is_default_safe_network(net)]),
            'blacklist_ips': len(self.blacklist),
            'blacklist_networks': len(self.blacklist_networks),
            'temp_blacklist_active': active_temp_blocks,
            'suspicious_ips': len(self.suspicious_ips),
            'recent_failed_attempts': recent_failed_attempts,
            'allowed_countries': len(self.allowed_countries),
            'blocked_countries': len(self.blocked_countries),
            'config': self.config.copy()
        }
    
    def cleanup_old_data(self):
        """Clean up old security data."""
        current_time = datetime.now(timezone.utc)
        
        # Clean expired temporary blacklist entries
        expired_ips = [
            ip for ip, expiry in self.temp_blacklist.items()
            if expiry <= current_time
        ]
        for ip in expired_ips:
            del self.temp_blacklist[ip]
        
        # Clean old failed attempts (older than 24 hours)
        cutoff_time = current_time - timedelta(hours=24)
        for ip in list(self.failed_attempts.keys()):
            self.failed_attempts[ip] = [
                attempt for attempt in self.failed_attempts[ip]
                if attempt > cutoff_time
            ]
            if not self.failed_attempts[ip]:
                del self.failed_attempts[ip]
        
        # Clean old suspicious IP data (older than 7 days)
        cutoff_time = current_time - timedelta(days=7)
        for ip in list(self.suspicious_ips.keys()):
            last_activity = datetime.fromisoformat(self.suspicious_ips[ip]['last_activity'])
            if last_activity < cutoff_time:
                del self.suspicious_ips[ip]
        
        if expired_ips:
            self._save_config()
            logger.info("Cleaned up %d expired security entries", len(expired_ips))


# Global IP security manager instance
ip_security = IPSecurityManager()
