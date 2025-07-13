"""
PlexiChat SIEM Integration
Integrates with Security Information and Event Management systems
"""

import asyncio
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)


class SIEMProvider(Enum):
    """Supported SIEM providers."""
    SPLUNK = "splunk"
    ELK_STACK = "elk_stack"
    QRADAR = "qradar"
    ARCSIGHT = "arcsight"
    SENTINEL = "azure_sentinel"
    CHRONICLE = "google_chronicle"
    SUMO_LOGIC = "sumo_logic"
    CUSTOM = "custom"


class EventSeverity(Enum):
    """Event severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class EventCategory(Enum):
    """Security event categories."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK_SECURITY = "network_security"
    APPLICATION_SECURITY = "application_security"
    DATA_PROTECTION = "data_protection"
    MALWARE = "malware"
    INTRUSION_DETECTION = "intrusion_detection"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    INCIDENT_RESPONSE = "incident_response"
    SYSTEM_MONITORING = "system_monitoring"


@dataclass
class SecurityEvent:
    """Standardized security event structure."""
    event_id: str
    timestamp: datetime
    source_system: str
    event_type: str
    category: EventCategory
    severity: EventSeverity
    title: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    user_agent: Optional[str] = None
    request_path: Optional[str] = None
    response_code: Optional[int] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None
    
    def to_cef(self) -> str:
        """Convert to Common Event Format (CEF)."""
        # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        cef_header = f"CEF:0|PlexiChat|PlexiChat Security|1.0|{self.event_type}|{self.title}|{self._severity_to_cef()}"
        
        extensions = []
        if self.source_ip:
            extensions.append(f"src={self.source_ip}")
        if self.destination_ip:
            extensions.append(f"dst={self.destination_ip}")
        if self.user_id:
            extensions.append(f"suser={self.user_id}")
        if self.request_path:
            extensions.append(f"request={self.request_path}")
        if self.response_code:
            extensions.append(f"response={self.response_code}")
        
        extensions.append(f"msg={self.description}")
        extensions.append(f"cat={self.category.value}")
        
        return f"{cef_header}|{' '.join(extensions)}"
    
    def to_leef(self) -> str:
        """Convert to Log Event Extended Format (LEEF)."""
        # LEEF:Version|Vendor|Product|Version|EventID|Delimiter|[Attributes]
        leef_header = f"LEEF:2.0|PlexiChat|PlexiChat Security|1.0|{self.event_type}|^"
        
        attributes = [
            f"devTime={int(self.timestamp.timestamp())}",
            f"severity={self.severity.value}",
            f"cat={self.category.value}",
            f"title={self.title}",
            f"msg={self.description}"
        ]
        
        if self.source_ip:
            attributes.append(f"src={self.source_ip}")
        if self.user_id:
            attributes.append(f"usrName={self.user_id}")
        
        return f"{leef_header}^{'^'.join(attributes)}"
    
    def _severity_to_cef(self) -> int:
        """Convert severity to CEF numeric value."""
        severity_map = {
            EventSeverity.CRITICAL: 10,
            EventSeverity.HIGH: 8,
            EventSeverity.MEDIUM: 5,
            EventSeverity.LOW: 3,
            EventSeverity.INFORMATIONAL: 1
        }
        return severity_map.get(self.severity, 1)


@dataclass
class SIEMConfiguration:
    """SIEM integration configuration."""
    provider: SIEMProvider
    endpoint_url: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    index_name: Optional[str] = None
    source_type: Optional[str] = None
    format: str = "json"  # json, cef, leef, syslog
    batch_size: int = 100
    batch_timeout: int = 30
    retry_attempts: int = 3
    retry_delay: int = 5
    enabled: bool = True
    ssl_verify: bool = True
    custom_headers: Dict[str, str] = field(default_factory=dict)


class SIEMIntegration:
    """
    SIEM Integration Manager.
    
    Features:
    - Multi-provider support (Splunk, ELK, QRadar, etc.)
    - Event normalization and correlation
    - Batch processing for performance
    - Automatic retry and failover
    - Real-time and batch event forwarding
    - Custom event enrichment
    - Compliance reporting
    """
    
    def __init__(self):
        self.configurations: Dict[str, SIEMConfiguration] = {}
        self.event_queue: List[SecurityEvent] = []
        self.batch_timer: Optional[asyncio.Task] = None
        self.statistics = {
            "events_sent": 0,
            "events_failed": 0,
            "last_batch_sent": None,
            "provider_stats": {}
        }
        self.running = False
    
    def add_siem_provider(self, name: str, config: SIEMConfiguration):
        """Add a SIEM provider configuration."""
        self.configurations[name] = config
        self.statistics["provider_stats"][name] = {
            "events_sent": 0,
            "events_failed": 0,
            "last_success": None,
            "last_failure": None
        }
        logger.info(f"✅ Added SIEM provider: {name} ({config.provider.value})")
    
    async def start(self):
        """Start the SIEM integration service."""
        if self.running:
            return
        
        self.running = True
        self.batch_timer = asyncio.create_task(self._batch_processor())
        logger.info("✅ SIEM integration service started")
    
    async def stop(self):
        """Stop the SIEM integration service."""
        self.running = False
        if self.batch_timer:
            self.batch_timer.cancel()
            try:
                await self.batch_timer
            except asyncio.CancelledError:
                pass
        
        # Send remaining events
        if self.event_queue:
            await self._send_batch()
        
        logger.info("✅ SIEM integration service stopped")
    
    async def send_event(self, event: SecurityEvent, immediate: bool = False):
        """Send a security event to SIEM systems."""
        if not self.configurations:
            logger.debug("No SIEM providers configured, skipping event")
            return
        
        # Add to queue
        self.event_queue.append(event)
        
        # Send immediately for critical events or if requested
        if immediate or event.severity == EventSeverity.CRITICAL:
            await self._send_batch()
    
    async def _batch_processor(self):
        """Process events in batches."""
        while self.running:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                if self.event_queue:
                    await self._send_batch()
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Batch processor error: {e}")
    
    async def _send_batch(self):
        """Send a batch of events to all configured SIEM providers."""
        if not self.event_queue:
            return
        
        # Get batch of events
        batch_size = min(100, len(self.event_queue))  # Max 100 events per batch
        events_to_send = self.event_queue[:batch_size]
        
        # Send to each provider
        for provider_name, config in self.configurations.items():
            if not config.enabled:
                continue
            
            try:
                await self._send_to_provider(provider_name, config, events_to_send)
                self.statistics["provider_stats"][provider_name]["events_sent"] += len(events_to_send)
                self.statistics["provider_stats"][provider_name]["last_success"] = datetime.now(timezone.utc)
                
            except Exception as e:
                logger.error(f"Failed to send events to {provider_name}: {e}")
                self.statistics["provider_stats"][provider_name]["events_failed"] += len(events_to_send)
                self.statistics["provider_stats"][provider_name]["last_failure"] = datetime.now(timezone.utc)
        
        # Remove sent events from queue
        self.event_queue = self.event_queue[batch_size:]
        self.statistics["events_sent"] += len(events_to_send)
        self.statistics["last_batch_sent"] = datetime.now(timezone.utc)
        
        logger.debug(f"Sent batch of {len(events_to_send)} events to SIEM providers")
    
    async def _send_to_provider(self, provider_name: str, config: SIEMConfiguration, events: List[SecurityEvent]):
        """Send events to a specific SIEM provider."""
        if config.provider == SIEMProvider.SPLUNK:
            await self._send_to_splunk(config, events)
        elif config.provider == SIEMProvider.ELK_STACK:
            await self._send_to_elasticsearch(config, events)
        elif config.provider == SIEMProvider.CUSTOM:
            await self._send_to_custom(config, events)
        else:
            # Generic HTTP endpoint
            await self._send_to_http_endpoint(config, events)
    
    async def _send_to_splunk(self, config: SIEMConfiguration, events: List[SecurityEvent]):
        """Send events to Splunk HEC (HTTP Event Collector)."""
        headers = {
            "Authorization": f"Splunk {config.api_key}",
            "Content-Type": "application/json"
        }
        headers.update(config.custom_headers)
        
        # Format events for Splunk
        splunk_events = []
        for event in events:
            splunk_event = {
                "time": int(event.timestamp.timestamp()),
                "source": "plexichat",
                "sourcetype": config.source_type or "plexichat:security",
                "index": config.index_name or "main",
                "event": asdict(event)
            }
            splunk_events.append(splunk_event)
        
        # Send to Splunk
        async with aiohttp.ClientSession() as session:
            for attempt in range(config.retry_attempts):
                try:
                    async with session.post(
                        config.endpoint_url,
                        headers=headers,
                        json=splunk_events,
                        ssl=config.ssl_verify
                    ) as response:
                        if response.status == 200:
                            return
                        else:
                            raise Exception(f"Splunk returned status {response.status}")
                
                except Exception:
                    if attempt == config.retry_attempts - 1:
                        raise
                    await asyncio.sleep(config.retry_delay * (attempt + 1))
    
    async def _send_to_elasticsearch(self, config: SIEMConfiguration, events: List[SecurityEvent]):
        """Send events to Elasticsearch."""
        headers = {"Content-Type": "application/x-ndjson"}
        if config.api_key:
            headers["Authorization"] = f"ApiKey {config.api_key}"
        elif config.username and config.password:
            import base64
            credentials = base64.b64encode(f"{config.username}:{config.password}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"
        
        headers.update(config.custom_headers)
        
        # Format for Elasticsearch bulk API
        bulk_data = []
        for event in events:
            index_action = {
                "index": {
                    "_index": config.index_name or "plexichat-security",
                    "_type": "_doc"
                }
            }
            bulk_data.append(json.dumps(index_action))
            bulk_data.append(json.dumps(asdict(event), default=str))
        
        bulk_body = "\n".join(bulk_data) + "\n"
        
        # Send to Elasticsearch
        async with aiohttp.ClientSession() as session:
            for attempt in range(config.retry_attempts):
                try:
                    async with session.post(
                        f"{config.endpoint_url}/_bulk",
                        headers=headers,
                        data=bulk_body,
                        ssl=config.ssl_verify
                    ) as response:
                        if response.status in [200, 201]:
                            return
                        else:
                            raise Exception(f"Elasticsearch returned status {response.status}")
                
                except Exception:
                    if attempt == config.retry_attempts - 1:
                        raise
                    await asyncio.sleep(config.retry_delay * (attempt + 1))
    
    async def _send_to_custom(self, config: SIEMConfiguration, events: List[SecurityEvent]):
        """Send events to custom HTTP endpoint."""
        await self._send_to_http_endpoint(config, events)
    
    async def _send_to_http_endpoint(self, config: SIEMConfiguration, events: List[SecurityEvent]):
        """Send events to generic HTTP endpoint."""
        headers = {"Content-Type": "application/json"}
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"
        headers.update(config.custom_headers)
        
        # Format events based on configuration
        if config.format == "cef":
            payload = [event.to_cef() for event in events]
        elif config.format == "leef":
            payload = [event.to_leef() for event in events]
        else:
            payload = [asdict(event) for event in events]
        
        async with aiohttp.ClientSession() as session:
            for attempt in range(config.retry_attempts):
                try:
                    async with session.post(
                        config.endpoint_url,
                        headers=headers,
                        json=payload,
                        ssl=config.ssl_verify
                    ) as response:
                        if response.status in [200, 201, 202]:
                            return
                        else:
                            raise Exception(f"HTTP endpoint returned status {response.status}")
                
                except Exception:
                    if attempt == config.retry_attempts - 1:
                        raise
                    await asyncio.sleep(config.retry_delay * (attempt + 1))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get SIEM integration statistics."""
        return {
            "running": self.running,
            "configured_providers": len(self.configurations),
            "queue_size": len(self.event_queue),
            "statistics": self.statistics
        }


# Global SIEM integration instance
siem_integration = SIEMIntegration()
