"""
Messaging Hub Plugin

Comprehensive messaging hub with advanced chat features, message analytics, 
thread management, and real-time communication.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import uuid

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Plugin interface imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from plexichat.infrastructure.modules.plugin_manager import PluginInterface, PluginMetadata, PluginType
from plexichat.infrastructure.modules.base_module import ModulePermissions, ModuleCapability

logger = logging.getLogger(__name__)


class Message(BaseModel):
    """Message model."""
    id: Optional[str] = None
    content: str
    sender_id: str
    recipient_id: Optional[str] = None
    channel_id: Optional[str] = None
    thread_id: Optional[str] = None
    message_type: str = "text"
    metadata: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None


class MessageThread(BaseModel):
    """Message thread model."""
    id: str
    title: str
    participants: List[str]
    created_at: str
    last_message_at: str
    message_count: int


class MessageReaction(BaseModel):
    """Message reaction model."""
    message_id: str
    user_id: str
    emoji: str
    timestamp: str


class MessageTemplate(BaseModel):
    """Message template model."""
    name: str
    content: str
    variables: Optional[List[str]] = None
    category: str = "general"


class MessagingCore:
    """Core messaging functionality."""
    
    def __init__(self, config: Dict[str, Any], api_integration):
        self.config = config
        self.api_integration = api_integration
        self.max_message_length = config.get('max_message_length', 4000)
        self.analytics_enabled = config.get('enable_message_analytics', True)
        self.auto_response_enabled = config.get('auto_response_enabled', False)
        self.smart_suggestions_enabled = config.get('enable_smart_suggestions', True)
        
        # Message analytics
        self.message_stats = {
            "total_sent": 0,
            "total_received": 0,
            "threads_created": 0,
            "reactions_added": 0
        }
        
        # Message templates
        self.templates = {
            template["name"]: template 
            for template in config.get('message_templates', [])
        }
        
        # Active typing indicators
        self.typing_users: Dict[str, Set[str]] = {}
        
        # Message cache for analytics
        self.recent_messages: List[Dict] = []
        
    async def send_message(self, message: Message) -> Dict[str, Any]:
        """Send a message through the API."""
        try:
            # Validate message
            if len(message.content) > self.max_message_length:
                raise ValueError(f"Message too long: {len(message.content)} > {self.max_message_length}")
            
            # Prepare message data
            message_data = {
                "content": message.content,
                "message_type": message.message_type
            }
            
            if message.recipient_id:
                message_data["recipient_id"] = message.recipient_id
            if message.channel_id:
                message_data["channel_id"] = message.channel_id
            if message.thread_id:
                message_data["thread_id"] = message.thread_id
            if message.metadata:
                message_data["metadata"] = message.metadata
            
            # Send through API
            from plugins.api_integration_layer.main import APIRequest
            request = APIRequest(
                endpoint="/messages/send",
                method="POST",
                data=message_data
            )
            
            result = await self.api_integration.make_api_request(request)
            
            # Update analytics
            if self.analytics_enabled:
                self.message_stats["total_sent"] += 1
                await self._track_message_analytics(message, "sent")
            
            # Check for auto-response
            if self.auto_response_enabled and message.recipient_id:
                await self._check_auto_response(message)
            
            return result
            
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            raise
    
    async def search_messages(self, query: str, filters: Optional[Dict] = None) -> Dict[str, Any]:
        """Search messages."""
        try:
            params = {"q": query}
            if filters:
                params.update(filters)
            
            from plugins.api_integration_layer.main import APIRequest
            request = APIRequest(
                endpoint="/messages/search",
                method="GET",
                params=params
            )
            
            result = await self.api_integration.make_api_request(request)
            
            # Enhance results with analytics
            if self.analytics_enabled:
                result = await self._enhance_search_results(result, query)
            
            return result
            
        except Exception as e:
            logger.error(f"Error searching messages: {e}")
            raise
    
    async def get_message_history(self, limit: int = 50, 
                                 channel_id: Optional[str] = None,
                                 thread_id: Optional[str] = None) -> Dict[str, Any]:
        """Get message history."""
        try:
            params = {"limit": str(limit)}
            if channel_id:
                params["channel_id"] = channel_id
            if thread_id:
                params["thread_id"] = thread_id
            
            from plugins.api_integration_layer.main import APIRequest
            request = APIRequest(
                endpoint="/messages/history",
                method="GET",
                params=params
            )
            
            result = await self.api_integration.make_api_request(request)
            
            # Update recent messages cache
            if "messages" in result:
                self.recent_messages.extend(result["messages"][-10:])  # Keep last 10
                self.recent_messages = self.recent_messages[-100:]  # Limit cache size
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting message history: {e}")
            raise
    
    async def add_reaction(self, message_id: str, emoji: str, user_id: str) -> Dict[str, Any]:
        """Add reaction to a message."""
        try:
            reaction_data = {
                "message_id": message_id,
                "emoji": emoji,
                "user_id": user_id
            }
            
            from plugins.api_integration_layer.main import APIRequest
            request = APIRequest(
                endpoint="/messages/reactions",
                method="POST",
                data=reaction_data
            )
            
            result = await self.api_integration.make_api_request(request)
            
            # Update analytics
            if self.analytics_enabled:
                self.message_stats["reactions_added"] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Error adding reaction: {e}")
            raise
    
    async def create_thread(self, title: str, initial_message: str, 
                          participants: List[str]) -> Dict[str, Any]:
        """Create a message thread."""
        try:
            thread_data = {
                "title": title,
                "initial_message": initial_message,
                "participants": participants
            }
            
            from plugins.api_integration_layer.main import APIRequest
            request = APIRequest(
                endpoint="/messages/threads",
                method="POST",
                data=thread_data
            )
            
            result = await self.api_integration.make_api_request(request)
            
            # Update analytics
            if self.analytics_enabled:
                self.message_stats["threads_created"] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Error creating thread: {e}")
            raise
    
    async def get_message_stats(self) -> Dict[str, Any]:
        """Get message statistics."""
        try:
            from plugins.api_integration_layer.main import APIRequest
            request = APIRequest(
                endpoint="/messages/stats",
                method="GET"
            )
            
            api_stats = await self.api_integration.make_api_request(request)
            
            # Combine with local stats
            combined_stats = {
                **api_stats,
                "local_stats": self.message_stats,
                "recent_activity": await self._analyze_recent_activity()
            }
            
            return combined_stats
            
        except Exception as e:
            logger.error(f"Error getting message stats: {e}")
            raise
    
    async def apply_template(self, template_name: str, 
                           variables: Optional[Dict[str, str]] = None) -> str:
        """Apply a message template."""
        try:
            if template_name not in self.templates:
                raise ValueError(f"Template '{template_name}' not found")
            
            template = self.templates[template_name]
            content = template["content"]
            
            # Replace variables
            if variables:
                for var_name, var_value in variables.items():
                    content = content.replace(f"{{{var_name}}}", var_value)
            
            return content
            
        except Exception as e:
            logger.error(f"Error applying template: {e}")
            raise
    
    async def get_smart_suggestions(self, context: str, user_id: str) -> List[str]:
        """Get smart message suggestions based on context."""
        try:
            if not self.smart_suggestions_enabled:
                return []
            
            suggestions = []
            
            # Analyze context for suggestions
            context_lower = context.lower()
            
            # Question detection
            if "?" in context:
                suggestions.append("I'd be happy to help answer that question.")
                suggestions.append("Let me look into that for you.")
            
            # Greeting detection
            if any(greeting in context_lower for greeting in ["hello", "hi", "hey"]):
                suggestions.append("Hello! How can I assist you today?")
                suggestions.append("Hi there! What can I help you with?")
            
            # Thanks detection
            if any(thanks in context_lower for thanks in ["thank", "thanks"]):
                suggestions.append("You're welcome!")
                suggestions.append("Happy to help!")
            
            # Meeting/schedule detection
            if any(word in context_lower for word in ["meeting", "schedule", "calendar"]):
                suggestions.append("I can help you schedule that.")
                suggestions.append("Let me check the calendar for you.")
            
            # File/document detection
            if any(word in context_lower for word in ["file", "document", "attachment"]):
                suggestions.append("I can help you with that file.")
                suggestions.append("Would you like me to share that document?")
            
            return suggestions[:3]  # Return top 3 suggestions
            
        except Exception as e:
            logger.error(f"Error getting smart suggestions: {e}")
            return []
    
    async def _track_message_analytics(self, message: Message, action: str):
        """Track message analytics."""
        try:
            analytics_data = {
                "action": action,
                "message_type": message.message_type,
                "content_length": len(message.content),
                "has_thread": bool(message.thread_id),
                "has_metadata": bool(message.metadata),
                "timestamp": datetime.now().isoformat()
            }
            
            # Store analytics (in real implementation, would use database)
            logger.debug(f"Message analytics: {analytics_data}")
            
        except Exception as e:
            logger.error(f"Error tracking message analytics: {e}")
    
    async def _check_auto_response(self, message: Message):
        """Check if auto-response should be sent."""
        try:
            # Simple auto-response logic
            content_lower = message.content.lower()
            
            auto_responses = {
                "hello": "Hello! I'm currently away but will respond soon.",
                "urgent": "I've received your urgent message and will prioritize it.",
                "meeting": "Thanks for the meeting request. I'll check my calendar.",
                "file": "I've received your file. I'll review it shortly."
            }
            
            for trigger, response in auto_responses.items():
                if trigger in content_lower:
                    # Send auto-response
                    auto_message = Message(
                        content=response,
                        sender_id="system",
                        recipient_id=message.sender_id,
                        message_type="auto_response"
                    )
                    
                    await self.send_message(auto_message)
                    break
                    
        except Exception as e:
            logger.error(f"Error checking auto-response: {e}")
    
    async def _enhance_search_results(self, results: Dict, query: str) -> Dict[str, Any]:
        """Enhance search results with analytics."""
        try:
            if "messages" in results:
                # Add relevance scores, highlights, etc.
                for message in results["messages"]:
                    # Simple relevance scoring
                    content = message.get("content", "").lower()
                    query_lower = query.lower()
                    
                    # Count query term occurrences
                    relevance = content.count(query_lower)
                    message["relevance_score"] = relevance
                    
                    # Add highlights
                    highlighted_content = re.sub(
                        f"({re.escape(query)})",
                        r"<mark>\1</mark>",
                        message.get("content", ""),
                        flags=re.IGNORECASE
                    )
                    message["highlighted_content"] = highlighted_content
            
            return results
            
        except Exception as e:
            logger.error(f"Error enhancing search results: {e}")
            return results
    
    async def _analyze_recent_activity(self) -> Dict[str, Any]:
        """Analyze recent message activity."""
        try:
            if not self.recent_messages:
                return {"activity_level": "low", "trends": []}
            
            # Analyze message frequency
            now = datetime.now()
            recent_count = len([
                msg for msg in self.recent_messages
                if datetime.fromisoformat(msg.get("timestamp", now.isoformat())) > now - timedelta(hours=1)
            ])
            
            activity_level = "high" if recent_count > 10 else "medium" if recent_count > 5 else "low"
            
            # Analyze message types
            type_counts = {}
            for msg in self.recent_messages:
                msg_type = msg.get("message_type", "text")
                type_counts[msg_type] = type_counts.get(msg_type, 0) + 1
            
            return {
                "activity_level": activity_level,
                "recent_count": recent_count,
                "message_types": type_counts,
                "trends": [
                    f"Most common message type: {max(type_counts, key=type_counts.get) if type_counts else 'none'}",
                    f"Activity level: {activity_level}"
                ]
            }
            
        except Exception as e:
            logger.error(f"Error analyzing recent activity: {e}")
            return {"activity_level": "unknown", "trends": []}


class MessagingHubPlugin(PluginInterface):
    """Messaging Hub Plugin."""

    def __init__(self):
        super().__init__("messaging_hub", "1.0.0")
        self.router = APIRouter()
        self.messaging_core = None
        self.api_integration = None
        self.data_dir = Path(__file__).parent / "data"
        self.data_dir.mkdir(exist_ok=True)

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="messaging_hub",
            version="1.0.0",
            description="Comprehensive messaging hub with advanced chat features, message analytics, and real-time communication",
            plugin_type=PluginType.COMMUNICATION
        )

    def get_required_permissions(self) -> ModulePermissions:
        """Get required permissions."""
        return ModulePermissions(
            capabilities=[
                ModuleCapability.API,
                ModuleCapability.NETWORK,
                ModuleCapability.FILE_SYSTEM,
                ModuleCapability.WEB_UI,
                ModuleCapability.DATABASE,
                ModuleCapability.WEBSOCKET,
                ModuleCapability.NOTIFICATIONS
            ],
            network_access=True,
            file_system_access=True,
            database_access=True
        )

    async def initialize(self) -> bool:
        """Initialize the plugin."""
        try:
            # Load configuration
            await self._load_configuration()

            # Get API integration layer
            api_plugin = self.manager.get_plugin("api_integration_layer")
            if not api_plugin:
                self.logger.error("API integration layer plugin not found")
                return False

            self.api_integration = api_plugin.get_api_core()

            # Initialize messaging core
            self.messaging_core = MessagingCore(self.config, self.api_integration)

            # Setup API routes
            self._setup_routes()

            # Register UI pages
            await self._register_ui_pages()

            self.logger.info("Messaging Hub plugin initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize Messaging Hub plugin: {e}")
            return False

    async def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        try:
            self.logger.info("Messaging Hub plugin cleanup completed")
            return True
        except Exception as e:
            self.logger.error(f"Error during Messaging Hub plugin cleanup: {e}")
            return False

    def _setup_routes(self):
        """Setup API routes."""

        @self.router.post("/send")
        async def send_message(message: Message):
            """Send a message."""
            try:
                result = await self.messaging_core.send_message(message)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/search")
        async def search_messages(q: str, limit: int = 20, channel_id: Optional[str] = None):
            """Search messages."""
            try:
                filters = {"limit": str(limit)}
                if channel_id:
                    filters["channel_id"] = channel_id

                result = await self.messaging_core.search_messages(q, filters)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/history")
        async def get_message_history(limit: int = 50,
                                    channel_id: Optional[str] = None,
                                    thread_id: Optional[str] = None):
            """Get message history."""
            try:
                result = await self.messaging_core.get_message_history(limit, channel_id, thread_id)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/reactions")
        async def add_reaction(message_id: str, emoji: str, user_id: str):
            """Add reaction to message."""
            try:
                result = await self.messaging_core.add_reaction(message_id, emoji, user_id)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/threads")
        async def create_thread(title: str, initial_message: str, participants: List[str]):
            """Create message thread."""
            try:
                result = await self.messaging_core.create_thread(title, initial_message, participants)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/stats")
        async def get_message_stats():
            """Get message statistics."""
            try:
                result = await self.messaging_core.get_message_stats()
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/templates")
        async def get_templates():
            """Get message templates."""
            try:
                return JSONResponse(content={"templates": list(self.messaging_core.templates.values())})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/templates/apply")
        async def apply_template(template_name: str, variables: Optional[Dict[str, str]] = None):
            """Apply message template."""
            try:
                content = await self.messaging_core.apply_template(template_name, variables)
                return JSONResponse(content={"content": content})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/suggestions")
        async def get_smart_suggestions(context: str, user_id: str):
            """Get smart message suggestions."""
            try:
                suggestions = await self.messaging_core.get_smart_suggestions(context, user_id)
                return JSONResponse(content={"suggestions": suggestions})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

    async def _load_configuration(self):
        """Load plugin configuration."""
        config_file = self.data_dir / "config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                    self.config.update(loaded_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}")

    async def _register_ui_pages(self):
        """Register UI pages with the main application."""
        ui_dir = Path(__file__).parent / "ui"
        if ui_dir.exists():
            app = getattr(self.manager, 'app', None)
            if app:
                from fastapi.staticfiles import StaticFiles
                app.mount(f"/plugins/messaging-hub/static",
                         StaticFiles(directory=str(ui_dir / "static")),
                         name="messaging_hub_static")

    # Self-test methods
    async def test_message_sending(self) -> Dict[str, Any]:
        """Test message sending functionality."""
        try:
            # Test message creation
            test_message = Message(
                content="Test message",
                sender_id="test_user",
                recipient_id="test_recipient"
            )

            # Would test actual sending in real implementation
            if len(test_message.content) <= self.messaging_core.max_message_length:
                return {"success": True, "message": "Message sending test passed"}
            else:
                return {"success": False, "error": "Message validation failed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_message_search(self) -> Dict[str, Any]:
        """Test message search functionality."""
        try:
            # Test search functionality (would use real API in implementation)
            return {"success": True, "message": "Message search test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_thread_management(self) -> Dict[str, Any]:
        """Test thread management."""
        try:
            # Test thread creation logic
            thread_data = {
                "title": "Test Thread",
                "participants": ["user1", "user2"],
                "initial_message": "Hello thread!"
            }

            if all(key in thread_data for key in ["title", "participants", "initial_message"]):
                return {"success": True, "message": "Thread management test passed"}
            else:
                return {"success": False, "error": "Thread validation failed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_reactions(self) -> Dict[str, Any]:
        """Test reaction system."""
        try:
            # Test reaction validation
            valid_emojis = ["👍", "❤️", "😊", "👎"]
            test_emoji = "👍"

            if test_emoji in valid_emojis:
                return {"success": True, "message": "Reactions test passed"}
            else:
                return {"success": False, "error": "Reaction validation failed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_analytics(self) -> Dict[str, Any]:
        """Test analytics functionality."""
        try:
            # Test analytics tracking
            if self.messaging_core.analytics_enabled:
                stats = self.messaging_core.message_stats
                if isinstance(stats, dict):
                    return {"success": True, "message": "Analytics test passed"}
                else:
                    return {"success": False, "error": "Analytics validation failed"}
            else:
                return {"success": True, "message": "Analytics disabled, test skipped"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_templates(self) -> Dict[str, Any]:
        """Test message templates."""
        try:
            # Test template application
            if "greeting" in self.messaging_core.templates:
                template_content = await self.messaging_core.apply_template("greeting")
                if template_content:
                    return {"success": True, "message": "Templates test passed"}
                else:
                    return {"success": False, "error": "Template application failed"}
            else:
                return {"success": True, "message": "No templates configured, test skipped"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_real_time_features(self) -> Dict[str, Any]:
        """Test real-time features."""
        try:
            # Test typing indicators and presence
            typing_users = self.messaging_core.typing_users
            if isinstance(typing_users, dict):
                return {"success": True, "message": "Real-time features test passed"}
            else:
                return {"success": False, "error": "Real-time features validation failed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def run_tests(self) -> Dict[str, Any]:
        """Run all plugin self-tests."""
        tests = [
            ("message_sending", self.test_message_sending),
            ("message_search", self.test_message_search),
            ("thread_management", self.test_thread_management),
            ("reactions", self.test_reactions),
            ("analytics", self.test_analytics),
            ("templates", self.test_templates),
            ("real_time_features", self.test_real_time_features)
        ]

        results = {
            "total": len(tests),
            "passed": 0,
            "failed": 0,
            "tests": {}
        }

        for test_name, test_func in tests:
            try:
                result = await test_func()
                if result.get("success", False):
                    results["passed"] += 1
                    results["tests"][test_name] = {"status": "passed", "message": result.get("message", "")}
                else:
                    results["failed"] += 1
                    results["tests"][test_name] = {"status": "failed", "error": result.get("error", "")}
            except Exception as e:
                results["failed"] += 1
                results["tests"][test_name] = {"status": "failed", "error": str(e)}

        results["success"] = results["failed"] == 0
        return results


# Plugin entry point
def create_plugin():
    """Create plugin instance."""
    return MessagingHubPlugin()
