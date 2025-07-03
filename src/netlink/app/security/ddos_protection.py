"""
Advanced DDoS Protection System
Dynamic rate limiting, IP timeouts, blacklisting with appeal system.
"""

import time
import json
import hashlib
import asyncio
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import logging

logger = logging.getLogger("netlink.security.ddos")

@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_allowance: int = 10
    window_size: int = 60  # seconds
    
@dataclass
class IPStatus:
    """IP address status tracking."""
    ip: str
    first_seen: float
    last_seen: float
    total_requests: int = 0
    blocked_until: Optional[float] = None
    blacklist_level: int = 0  # 0=normal, 1=temp, 2=permanent
    violation_count: int = 0
    last_violation: Optional[float] = None
    user_agent: str = ""
    country: str = ""
    
class DynamicRateLimiter:
    """Dynamic rate limiting system that adapts to load."""
    
    def __init__(self):
        self.base_config = RateLimitConfig()
        self.current_config = RateLimitConfig()
        self.system_load = 0.0
        self.active_connections = 0
        self.requests_per_second = deque(maxlen=60)  # Last 60 seconds
        
        # Load adaptation thresholds
        self.load_thresholds = {
            "low": 0.3,      # < 30% load - relaxed limits
            "normal": 0.7,   # 30-70% load - normal limits  
            "high": 0.9,     # 70-90% load - strict limits
            "critical": 1.0  # > 90% load - emergency limits
        }
        
        # Dynamic multipliers based on load
        self.load_multipliers = {
            "low": 1.5,      # 50% more requests allowed
            "normal": 1.0,   # Normal limits
            "high": 0.6,     # 40% fewer requests allowed
            "critical": 0.3  # 70% fewer requests allowed
        }
        
    def update_system_metrics(self, cpu_percent: float, memory_percent: float, 
                            active_connections: int, requests_last_second: int):
        """Update system metrics for dynamic adjustment."""
        # Calculate combined load score
        self.system_load = (cpu_percent + memory_percent) / 200.0
        self.active_connections = active_connections
        self.requests_per_second.append(requests_last_second)
        
        # Adjust rate limits based on load
        self._adjust_rate_limits()
    
    def _adjust_rate_limits(self):
        """Dynamically adjust rate limits based on system load."""
        # Determine load level
        if self.system_load < self.load_thresholds["low"]:
            load_level = "low"
        elif self.system_load < self.load_thresholds["normal"]:
            load_level = "normal"
        elif self.system_load < self.load_thresholds["high"]:
            load_level = "high"
        else:
            load_level = "critical"
        
        # Apply multiplier
        multiplier = self.load_multipliers[load_level]
        
        self.current_config.requests_per_minute = int(
            self.base_config.requests_per_minute * multiplier
        )
        self.current_config.requests_per_hour = int(
            self.base_config.requests_per_hour * multiplier
        )
        self.current_config.burst_allowance = int(
            self.base_config.burst_allowance * multiplier
        )
        
        logger.debug(f"Rate limits adjusted for {load_level} load: "
                    f"{self.current_config.requests_per_minute}/min")
    
    def get_current_limits(self) -> RateLimitConfig:
        """Get current rate limiting configuration."""
        return self.current_config
    
    def get_load_status(self) -> Dict[str, any]:
        """Get current load status."""
        avg_rps = sum(self.requests_per_second) / len(self.requests_per_second) if self.requests_per_second else 0
        
        return {
            "system_load": self.system_load,
            "active_connections": self.active_connections,
            "avg_requests_per_second": avg_rps,
            "current_limits": asdict(self.current_config),
            "load_level": self._get_load_level()
        }
    
    def _get_load_level(self) -> str:
        """Get current load level."""
        if self.system_load < self.load_thresholds["low"]:
            return "low"
        elif self.system_load < self.load_thresholds["normal"]:
            return "normal"
        elif self.system_load < self.load_thresholds["high"]:
            return "high"
        else:
            return "critical"

class IPBlacklistManager:
    """Manages IP blacklisting with appeal system."""
    
    def __init__(self):
        self.config_dir = Path("config")
        self.config_dir.mkdir(exist_ok=True)
        
        self.blacklist_file = self.config_dir / "ip_blacklist.json"
        self.appeals_file = self.config_dir / "blacklist_appeals.json"
        
        self.ip_status: Dict[str, IPStatus] = {}
        self.temp_blacklist: Set[str] = set()
        self.permanent_blacklist: Set[str] = set()
        self.appeals: Dict[str, Dict] = {}
        
        # Timeout configurations (in seconds)
        self.timeout_levels = {
            1: 300,      # 5 minutes
            2: 1800,     # 30 minutes  
            3: 3600,     # 1 hour
            4: 21600,    # 6 hours
            5: 86400,    # 24 hours
        }
        
        self.load_blacklist_data()
    
    def load_blacklist_data(self):
        """Load blacklist data from storage."""
        try:
            if self.blacklist_file.exists():
                with open(self.blacklist_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    for ip_data in data.get('ip_status', []):
                        ip_status = IPStatus(**ip_data)
                        self.ip_status[ip_status.ip] = ip_status
                        
                        if ip_status.blacklist_level == 1:
                            self.temp_blacklist.add(ip_status.ip)
                        elif ip_status.blacklist_level == 2:
                            self.permanent_blacklist.add(ip_status.ip)
            
            if self.appeals_file.exists():
                with open(self.appeals_file, 'r', encoding='utf-8') as f:
                    self.appeals = json.load(f)
                    
        except Exception as e:
            logger.error(f"Error loading blacklist data: {e}")
    
    def save_blacklist_data(self):
        """Save blacklist data to storage."""
        try:
            # Prepare data for serialization
            data = {
                'ip_status': [asdict(status) for status in self.ip_status.values()],
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.blacklist_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            with open(self.appeals_file, 'w', encoding='utf-8') as f:
                json.dump(self.appeals, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving blacklist data: {e}")
    
    def record_request(self, ip: str, user_agent: str = "", country: str = ""):
        """Record a request from an IP address."""
        current_time = time.time()
        
        if ip not in self.ip_status:
            self.ip_status[ip] = IPStatus(
                ip=ip,
                first_seen=current_time,
                last_seen=current_time,
                user_agent=user_agent,
                country=country
            )
        
        status = self.ip_status[ip]
        status.last_seen = current_time
        status.total_requests += 1
        
        # Update user agent and country if provided
        if user_agent:
            status.user_agent = user_agent
        if country:
            status.country = country
    
    def check_rate_violation(self, ip: str, requests_in_window: int, 
                           rate_config: RateLimitConfig) -> bool:
        """Check if IP has violated rate limits."""
        if requests_in_window > rate_config.requests_per_minute:
            self._record_violation(ip)
            return True
        return False
    
    def _record_violation(self, ip: str):
        """Record a rate limit violation."""
        current_time = time.time()
        
        if ip not in self.ip_status:
            self.record_request(ip)
        
        status = self.ip_status[ip]
        status.violation_count += 1
        status.last_violation = current_time
        
        # Determine timeout based on violation count
        timeout_level = min(status.violation_count, 5)
        timeout_duration = self.timeout_levels[timeout_level]
        
        # Apply timeout
        status.blocked_until = current_time + timeout_duration
        
        # Escalate to blacklist if too many violations
        if status.violation_count >= 3:
            self._escalate_to_blacklist(ip, status)
        
        logger.warning(f"Rate violation recorded for {ip}: "
                      f"violation #{status.violation_count}, "
                      f"blocked for {timeout_duration}s")
    
    def _escalate_to_blacklist(self, ip: str, status: IPStatus):
        """Escalate IP to blacklist based on violation history."""
        if status.violation_count >= 5:
            # Permanent blacklist
            status.blacklist_level = 2
            self.permanent_blacklist.add(ip)
            self.temp_blacklist.discard(ip)
            logger.error(f"IP {ip} added to permanent blacklist")
        elif status.violation_count >= 3:
            # Temporary blacklist
            status.blacklist_level = 1
            self.temp_blacklist.add(ip)
            logger.warning(f"IP {ip} added to temporary blacklist")
        
        self.save_blacklist_data()
    
    def is_blocked(self, ip: str) -> Tuple[bool, str]:
        """Check if IP is currently blocked."""
        current_time = time.time()
        
        # Check permanent blacklist
        if ip in self.permanent_blacklist:
            return True, "permanently_blacklisted"
        
        # Check temporary blacklist
        if ip in self.temp_blacklist:
            return True, "temporarily_blacklisted"
        
        # Check timeout
        if ip in self.ip_status:
            status = self.ip_status[ip]
            if status.blocked_until and current_time < status.blocked_until:
                remaining = int(status.blocked_until - current_time)
                return True, f"timeout_{remaining}s"
        
        return False, "allowed"
    
    def submit_appeal(self, ip: str, reason: str, contact_email: str) -> str:
        """Submit an appeal for blacklist removal."""
        appeal_id = hashlib.md5(f"{ip}{time.time()}".encode()).hexdigest()[:8]
        
        appeal = {
            "appeal_id": appeal_id,
            "ip": ip,
            "reason": reason,
            "contact_email": contact_email,
            "submitted_at": datetime.now().isoformat(),
            "status": "pending",
            "reviewed_by": None,
            "reviewed_at": None,
            "decision": None
        }
        
        self.appeals[appeal_id] = appeal
        self.save_blacklist_data()
        
        logger.info(f"Appeal submitted for IP {ip}: {appeal_id}")
        return appeal_id
    
    def process_appeal(self, appeal_id: str, decision: str, reviewer: str, 
                      notes: str = "") -> bool:
        """Process an appeal (approve/deny)."""
        if appeal_id not in self.appeals:
            return False
        
        appeal = self.appeals[appeal_id]
        appeal["status"] = "reviewed"
        appeal["decision"] = decision
        appeal["reviewed_by"] = reviewer
        appeal["reviewed_at"] = datetime.now().isoformat()
        appeal["notes"] = notes
        
        if decision == "approved":
            ip = appeal["ip"]
            # Remove from blacklists
            self.temp_blacklist.discard(ip)
            self.permanent_blacklist.discard(ip)
            
            # Reset IP status
            if ip in self.ip_status:
                status = self.ip_status[ip]
                status.blacklist_level = 0
                status.blocked_until = None
                status.violation_count = 0
            
            logger.info(f"Appeal {appeal_id} approved: IP {ip} removed from blacklist")
        
        self.save_blacklist_data()
        return True
    
    def get_blacklist_stats(self) -> Dict[str, any]:
        """Get blacklist statistics."""
        current_time = time.time()
        
        # Count active timeouts
        active_timeouts = sum(
            1 for status in self.ip_status.values()
            if status.blocked_until and current_time < status.blocked_until
        )
        
        return {
            "total_tracked_ips": len(self.ip_status),
            "temp_blacklisted": len(self.temp_blacklist),
            "permanently_blacklisted": len(self.permanent_blacklist),
            "active_timeouts": active_timeouts,
            "pending_appeals": len([a for a in self.appeals.values() if a["status"] == "pending"]),
            "total_appeals": len(self.appeals)
        }

class AdvancedDDoSProtection:
    """Main DDoS protection coordinator."""
    
    def __init__(self):
        self.rate_limiter = DynamicRateLimiter()
        self.blacklist_manager = IPBlacklistManager()
        self.request_tracker = defaultdict(lambda: deque(maxlen=100))
        
        # Performance monitoring
        self.last_metrics_update = 0
        self.metrics_update_interval = 5  # seconds
        
    async def check_request(self, ip: str, user_agent: str = "", 
                          country: str = "") -> Tuple[bool, str, Dict]:
        """Check if request should be allowed."""
        current_time = time.time()
        
        # Record the request
        self.blacklist_manager.record_request(ip, user_agent, country)
        
        # Check if IP is blocked
        is_blocked, block_reason = self.blacklist_manager.is_blocked(ip)
        if is_blocked:
            return False, block_reason, {"action": "blocked", "reason": block_reason}
        
        # Update system metrics periodically
        if current_time - self.last_metrics_update > self.metrics_update_interval:
            await self._update_system_metrics()
            self.last_metrics_update = current_time
        
        # Check rate limits
        self.request_tracker[ip].append(current_time)
        
        # Count requests in current window
        window_start = current_time - self.rate_limiter.current_config.window_size
        recent_requests = sum(
            1 for req_time in self.request_tracker[ip]
            if req_time > window_start
        )
        
        # Check for rate violation
        if self.blacklist_manager.check_rate_violation(
            ip, recent_requests, self.rate_limiter.current_config
        ):
            return False, "rate_limited", {
                "action": "rate_limited",
                "requests_in_window": recent_requests,
                "limit": self.rate_limiter.current_config.requests_per_minute
            }
        
        return True, "allowed", {
            "action": "allowed",
            "requests_in_window": recent_requests,
            "limit": self.rate_limiter.current_config.requests_per_minute
        }
    
    async def _update_system_metrics(self):
        """Update system metrics for dynamic rate limiting."""
        try:
            import psutil
            
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            
            # Count active connections (approximate)
            active_connections = len([
                tracker for tracker in self.request_tracker.values()
                if tracker and time.time() - tracker[-1] < 60
            ])
            
            # Count requests in last second
            current_time = time.time()
            requests_last_second = sum(
                sum(1 for req_time in tracker if current_time - req_time < 1)
                for tracker in self.request_tracker.values()
            )
            
            self.rate_limiter.update_system_metrics(
                cpu_percent, memory_percent, active_connections, requests_last_second
            )
            
        except ImportError:
            # psutil not available, use default metrics
            pass
        except Exception as e:
            logger.error(f"Error updating system metrics: {e}")
    
    def get_protection_stats(self) -> Dict[str, any]:
        """Get comprehensive protection statistics."""
        return {
            "rate_limiter": self.rate_limiter.get_load_status(),
            "blacklist": self.blacklist_manager.get_blacklist_stats(),
            "tracked_ips": len(self.request_tracker),
            "protection_active": True
        }
    
    def cleanup_old_data(self, max_age_hours: int = 24):
        """Clean up old tracking data."""
        current_time = time.time()
        cutoff_time = current_time - (max_age_hours * 3600)
        
        # Clean up request tracker
        for ip in list(self.request_tracker.keys()):
            # Remove old requests
            while (self.request_tracker[ip] and 
                   self.request_tracker[ip][0] < cutoff_time):
                self.request_tracker[ip].popleft()
            
            # Remove empty trackers
            if not self.request_tracker[ip]:
                del self.request_tracker[ip]
        
        # Clean up old IP status entries
        for ip in list(self.blacklist_manager.ip_status.keys()):
            status = self.blacklist_manager.ip_status[ip]
            if (status.last_seen < cutoff_time and 
                status.blacklist_level == 0 and 
                not status.blocked_until):
                del self.blacklist_manager.ip_status[ip]

# Global DDoS protection instance
ddos_protection = AdvancedDDoSProtection()
