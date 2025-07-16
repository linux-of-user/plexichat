"""
Advanced Client Plugin

Sophisticated client plugin demonstrating advanced functionality with AI integration,
real-time collaboration, voice features, and intelligent automation.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import websockets
import threading

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Plugin interface imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

try:
    from plexichat.infrastructure.modules.plugin_manager import PluginInterface, PluginMetadata, PluginType
except ImportError:
    # Fallback definitions
    class PluginInterface:
        def get_metadata(self) -> Dict[str, Any]:
            return {}

    class PluginMetadata:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    class PluginType:
        CLIENT = "client"

try:
    from plexichat.infrastructure.modules.base_module import ModulePermissions, ModuleCapability
except ImportError:
    # Fallback definitions
    class ModulePermissions:
        READ = "read"
        WRITE = "write"
        ADMIN = "admin"

    class ModuleCapability:
        MESSAGING = "messaging"
        AI_INTEGRATION = "ai_integration"

logger = logging.getLogger(__name__)


# Helper classes
class AIIntegration:
    """AI integration helper."""
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    async def process_message(self, message: str) -> str:
        return f"AI processed: {message}"

class VoiceProcessor:
    """Voice processing helper."""
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    async def process_audio(self, audio_data: bytes) -> str:
        return "Audio processed"

class AdvancedAnalytics:
    """Analytics helper."""
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    async def track_event(self, event: str, data: Dict[str, Any]):
        logger.info(f"Analytics: {event} - {data}")


class ChatMessage(BaseModel):
    """Chat message model."""
    id: str
    user_id: str
    content: str
    timestamp: str
    message_type: str = "text"
    metadata: Optional[Dict[str, Any]] = None


class CollaborationSession(BaseModel):
    """Collaboration session model."""
    session_id: str
    workspace_id: str
    participants: List[str]
    created_at: str
    last_activity: str


class AIRequest(BaseModel):
    """AI request model."""
    prompt: str
    context: Optional[Dict[str, Any]] = None
    model: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 1000


class VoiceCommand(BaseModel):
    """Voice command model."""
    command: str
    confidence: float
    timestamp: str
    user_id: str


class ConnectionManager:
    """WebSocket connection manager for real-time features."""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_sessions: Dict[str, Set[str]] = {}
        self.collaboration_rooms: Dict[str, Set[str]] = {}
    
    async def connect(self, websocket: WebSocket, user_id: str, session_id: str):
        """Connect a user to WebSocket."""
        await websocket.accept()
        self.active_connections[session_id] = websocket
        
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = set()
        self.user_sessions[user_id].add(session_id)
        
        logger.info(f"User {user_id} connected with session {session_id}")
    
    def disconnect(self, session_id: str, user_id: str):
        """Disconnect a user."""
        if session_id in self.active_connections:
            del self.active_connections[session_id]
        
        if user_id in self.user_sessions:
            self.user_sessions[user_id].discard(session_id)
            if not self.user_sessions[user_id]:
                del self.user_sessions[user_id]
        
        logger.info(f"User {user_id} disconnected session {session_id}")
    
    async def send_personal_message(self, message: str, session_id: str):
        """Send message to specific session."""
        if session_id in self.active_connections:
            websocket = self.active_connections[session_id]
            await websocket.send_text(message)
    
    async def send_to_user(self, message: str, user_id: str):
        """Send message to all sessions of a user."""
        if user_id in self.user_sessions:
            for session_id in self.user_sessions[user_id]:
                await self.send_personal_message(message, session_id)
    
    async def broadcast_to_room(self, message: str, room_id: str):
        """Broadcast message to all users in a collaboration room."""
        if room_id in self.collaboration_rooms:
            for session_id in self.collaboration_rooms[room_id]:
                await self.send_personal_message(message, session_id)
    
    def join_room(self, session_id: str, room_id: str):
        """Join a collaboration room."""
        if room_id not in self.collaboration_rooms:
            self.collaboration_rooms[room_id] = set()
        self.collaboration_rooms[room_id].add(session_id)
    
    def leave_room(self, session_id: str, room_id: str):
        """Leave a collaboration room."""
        if room_id in self.collaboration_rooms:
            self.collaboration_rooms[room_id].discard(session_id)
            if not self.collaboration_rooms[room_id]:
                del self.collaboration_rooms[room_id]


class AIIntegration:
    """AI integration for intelligent features."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model = config.get('ai_model', 'gpt-4')
        self.conversation_history: Dict[str, List[Dict]] = {}
        self.user_preferences: Dict[str, Dict] = {}
        
    async def process_chat_message(self, message: str, user_id: str, 
                                 context: Optional[Dict] = None) -> Dict[str, Any]:
        """Process chat message with AI."""
        try:
            # Initialize conversation history for user
            if user_id not in self.conversation_history:
                self.conversation_history[user_id] = []
            
            # Add user message to history
            self.conversation_history[user_id].append({
                "role": "user",
                "content": message,
                "timestamp": datetime.now().isoformat()
            })
            
            # Simulate AI response (in real implementation, would call OpenAI API)
            ai_response = await self._generate_ai_response(message, user_id, context)
            
            # Add AI response to history
            self.conversation_history[user_id].append({
                "role": "assistant",
                "content": ai_response,
                "timestamp": datetime.now().isoformat()
            })
            
            return {
                "response": ai_response,
                "confidence": 0.95,
                "processing_time": 0.5,
                "model_used": self.model,
                "context_used": bool(context)
            }
            
        except Exception as e:
            logger.error(f"Error processing AI chat: {e}")
            return {
                "response": "I apologize, but I'm having trouble processing your request right now.",
                "confidence": 0.0,
                "error": str(e)
            }
    
    async def _generate_ai_response(self, message: str, user_id: str, 
                                  context: Optional[Dict] = None) -> str:
        """Generate AI response (placeholder implementation)."""
        # In a real implementation, this would call OpenAI API
        responses = [
            f"I understand you're asking about: {message}. Let me help you with that.",
            f"That's an interesting question about {message}. Here's what I think...",
            f"Based on your message '{message}', I can suggest several approaches.",
            "I'm here to help! Could you provide more details about what you need?",
            "Let me analyze that for you and provide a comprehensive response."
        ]
        
        # Simulate processing delay
        await asyncio.sleep(0.5)
        
        import random
        return random.choice(responses)
    
    async def analyze_user_behavior(self, user_id: str, actions: List[Dict]) -> Dict[str, Any]:
        """Analyze user behavior for insights."""
        try:
            # Simulate behavior analysis
            patterns = {
                "most_active_time": "14:00-16:00",
                "preferred_features": ["chat", "collaboration", "file_management"],
                "productivity_score": 85,
                "engagement_level": "high",
                "suggestions": [
                    "Consider using voice commands for faster navigation",
                    "Try the new collaboration features for team projects",
                    "Enable smart automation to save time"
                ]
            }
            
            return patterns
            
        except Exception as e:
            logger.error(f"Error analyzing user behavior: {e}")
            return {}
    
    async def generate_smart_suggestions(self, user_id: str, 
                                       current_context: Dict) -> List[str]:
        """Generate smart suggestions based on context."""
        try:
            suggestions = [
                "Would you like me to summarize the recent chat messages?",
                "I notice you're working on a project. Should I create a collaboration room?",
                "Based on your activity, you might want to enable auto-save.",
                "I can help optimize your workflow. Would you like suggestions?",
                "Consider using voice commands for hands-free operation."
            ]
            
            # Filter suggestions based on context
            relevant_suggestions = []
            for suggestion in suggestions:
                if self._is_suggestion_relevant(suggestion, current_context):
                    relevant_suggestions.append(suggestion)
            
            return relevant_suggestions[:3]  # Return top 3 suggestions
            
        except Exception as e:
            logger.error(f"Error generating suggestions: {e}")
            return []
    
    def _is_suggestion_relevant(self, suggestion: str, context: Dict) -> bool:
        """Check if suggestion is relevant to current context."""
        # Simple relevance check (in real implementation, would use ML)
        keywords = suggestion.lower().split()
        context_text = str(context).lower()
        
        return any(keyword in context_text for keyword in keywords)


class VoiceProcessor:
    """Voice recognition and synthesis processor."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enable_voice', True)
        self.recognition_active = False
        
    async def process_voice_command(self, audio_data: bytes, user_id: str) -> Dict[str, Any]:
        """Process voice command from audio data."""
        try:
            if not self.enabled:
                return {"error": "Voice features are disabled"}
            
            # Simulate voice recognition (in real implementation, would use speech_recognition)
            command = await self._recognize_speech(audio_data)
            
            if command:
                # Process the recognized command
                result = await self._execute_voice_command(command, user_id)
                return {
                    "recognized_text": command,
                    "confidence": 0.9,
                    "action_taken": result,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {"error": "Could not recognize speech"}
                
        except Exception as e:
            logger.error(f"Error processing voice command: {e}")
            return {"error": str(e)}
    
    async def _recognize_speech(self, audio_data: bytes) -> Optional[str]:
        """Recognize speech from audio data."""
        # Placeholder implementation
        # In real implementation, would use speech_recognition library
        commands = [
            "open file manager",
            "start collaboration session",
            "show analytics dashboard",
            "run system scan",
            "create new project",
            "send message to team"
        ]
        
        import random
        return random.choice(commands)
    
    async def _execute_voice_command(self, command: str, user_id: str) -> str:
        """Execute recognized voice command."""
        command_lower = command.lower()
        
        if "file manager" in command_lower:
            return "Opening file manager"
        elif "collaboration" in command_lower:
            return "Starting collaboration session"
        elif "analytics" in command_lower:
            return "Showing analytics dashboard"
        elif "scan" in command_lower:
            return "Running system scan"
        elif "project" in command_lower:
            return "Creating new project"
        elif "message" in command_lower:
            return "Opening message composer"
        else:
            return f"Executing command: {command}"
    
    async def synthesize_speech(self, text: str) -> bytes:
        """Convert text to speech."""
        try:
            if not self.enabled:
                return b""
            
            # Placeholder implementation
            # In real implementation, would use pyttsx3 or similar
            logger.info(f"Synthesizing speech: {text}")
            return b"audio_data_placeholder"
            
        except Exception as e:
            logger.error(f"Error synthesizing speech: {e}")
            return b""


class AdvancedAnalytics:
    """Advanced analytics and insights engine."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.analytics_enabled = config.get('analytics', {}).get('user_behavior', True)
        self.user_data: Dict[str, List[Dict]] = {}
        self.insights_cache: Dict[str, Dict] = {}
        
    async def track_user_action(self, user_id: str, action: str, 
                              metadata: Optional[Dict] = None):
        """Track user action for analytics."""
        try:
            if not self.analytics_enabled:
                return
            
            if user_id not in self.user_data:
                self.user_data[user_id] = []
            
            action_data = {
                "action": action,
                "timestamp": datetime.now().isoformat(),
                "metadata": metadata or {}
            }
            
            self.user_data[user_id].append(action_data)
            
            # Keep only last 1000 actions per user
            if len(self.user_data[user_id]) > 1000:
                self.user_data[user_id] = self.user_data[user_id][-1000:]
                
        except Exception as e:
            logger.error(f"Error tracking user action: {e}")
    
    async def generate_insights(self, user_id: str) -> Dict[str, Any]:
        """Generate insights for user."""
        try:
            if user_id not in self.user_data:
                return {"message": "No data available for insights"}
            
            actions = self.user_data[user_id]
            
            # Calculate basic metrics
            total_actions = len(actions)
            unique_actions = len(set(action["action"] for action in actions))
            
            # Time-based analysis
            recent_actions = [
                action for action in actions
                if datetime.fromisoformat(action["timestamp"]) > datetime.now() - timedelta(hours=24)
            ]
            
            # Most common actions
            action_counts = {}
            for action in actions:
                action_name = action["action"]
                action_counts[action_name] = action_counts.get(action_name, 0) + 1
            
            most_common = sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            
            insights = {
                "total_actions": total_actions,
                "unique_actions": unique_actions,
                "recent_activity": len(recent_actions),
                "most_common_actions": most_common,
                "activity_trend": "increasing" if len(recent_actions) > total_actions * 0.3 else "stable",
                "engagement_score": min(100, (total_actions / 100) * 10),
                "recommendations": await self._generate_recommendations(user_id, actions)
            }
            
            # Cache insights
            self.insights_cache[user_id] = insights
            
            return insights
            
        except Exception as e:
            logger.error(f"Error generating insights: {e}")
            return {"error": str(e)}
    
    async def _generate_recommendations(self, user_id: str, actions: List[Dict]) -> List[str]:
        """Generate personalized recommendations."""
        recommendations = []
        
        # Analyze action patterns
        action_types = [action["action"] for action in actions]
        
        if "file_upload" in action_types and action_types.count("file_upload") > 10:
            recommendations.append("Consider using bulk file operations to save time")
        
        if "collaboration_join" in action_types:
            recommendations.append("Try voice commands for faster collaboration")
        
        if len(set(action_types)) < 5:
            recommendations.append("Explore more features to enhance your productivity")
        
        return recommendations


class AdvancedClientPlugin(PluginInterface):
    """Advanced Client Plugin with sophisticated features."""

    def __init__(self):
        super().__init__("advanced_client", "1.0.0")
        self.router = APIRouter()
        self.data_dir = Path(__file__).parent / "data"
        self.data_dir.mkdir(exist_ok=True)

        # Initialize components
        self.connection_manager = ConnectionManager()
        self.ai_integration = None
        self.voice_processor = None
        self.analytics = None
        self.api_integration = None

        # State management
        self.active_sessions: Dict[str, CollaborationSession] = {}
        self.chat_history: Dict[str, List[ChatMessage]] = {}
        self.user_preferences: Dict[str, Dict] = {}

    def get_metadata(self) -> Dict[str, Any]:
        """Get plugin metadata."""
        return {
            "name": "advanced_client",
            "version": "1.0.0",
            "description": "Advanced client plugin with AI integration, real-time collaboration, and intelligent automation",
            "plugin_type": "client"
        }

    def get_required_permissions(self) -> Dict[str, Any]:
        """Get required permissions."""
        return {
            "capabilities": [
                "ai",
                "network",
                "file_system",
                "web_ui",
                "database",
                "websocket",
                "notifications"
            ],
            "network_access": True,
            "file_system_access": True,
            "database_access": True
        }

    async def initialize(self) -> bool:
        """Initialize the plugin."""
        try:
            # Load configuration
            await self._load_configuration()

            # Initialize components
            self.ai_integration = AIIntegration(self.config)
            self.voice_processor = VoiceProcessor(self.config)
            self.analytics = AdvancedAnalytics(self.config)

            # Get API integration layer
            api_plugin = self.manager.get_plugin("api_integration_layer")
            if api_plugin:
                self.api_integration = api_plugin.get_api_core()

            # Setup API routes
            self._setup_routes()

            # Setup WebSocket endpoints
            self._setup_websockets()

            # Register UI pages
            await self._register_ui_pages()

            # Start background tasks
            await self._start_background_tasks()

            self.logger.info("Advanced Client plugin initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize Advanced Client plugin: {e}")
            return False

    async def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        try:
            # Close all WebSocket connections
            for session_id, websocket in self.connection_manager.active_connections.items():
                await websocket.close()

            self.logger.info("Advanced Client plugin cleanup completed")
            return True
        except Exception as e:
            self.logger.error(f"Error during Advanced Client plugin cleanup: {e}")
            return False

    def _setup_routes(self):
        """Setup API routes."""

        @self.router.post("/ai/chat")
        async def ai_chat(request: AIRequest, user_id: str = "default"):
            """AI chat endpoint."""
            try:
                result = await self.ai_integration.process_chat_message(
                    request.prompt, user_id, request.context
                )

                # Track user action
                if self.analytics:
                    await self.analytics.track_user_action(user_id, "ai_chat", {
                        "prompt_length": len(request.prompt),
                        "model": request.model or self.ai_integration.model
                    })

                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/voice/process")
        async def process_voice(audio_data: bytes, user_id: str = "default"):
            """Process voice command."""
            try:
                result = await self.voice_processor.process_voice_command(audio_data, user_id)

                # Track user action
                if self.analytics:
                    await self.analytics.track_user_action(user_id, "voice_command", {
                        "audio_length": len(audio_data)
                    })

                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/analytics/insights")
        async def get_insights(user_id: str = "default"):
            """Get user insights."""
            try:
                if self.analytics:
                    insights = await self.analytics.generate_insights(user_id)
                    return JSONResponse(content=insights)
                else:
                    return JSONResponse(content={"insights": [], "message": "Analytics not available"})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/collaboration/create")
        async def create_collaboration_session(workspace_id: str, user_id: str = "default"):
            """Create collaboration session."""
            try:
                session_id = str(uuid.uuid4())
                session = CollaborationSession(
                    session_id=session_id,
                    workspace_id=workspace_id,
                    participants=[user_id],
                    created_at=datetime.now().isoformat(),
                    last_activity=datetime.now().isoformat()
                )

                self.active_sessions[session_id] = session

                # Track user action
                if self.analytics:
                    await self.analytics.track_user_action(user_id, "collaboration_create", {
                        "workspace_id": workspace_id,
                        "session_id": session_id
                    })

                return JSONResponse(content=session.dict())
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/collaboration/sessions")
        async def get_collaboration_sessions(user_id: str = "default"):
            """Get user's collaboration sessions."""
            try:
                user_sessions = [
                    session.dict() for session in self.active_sessions.values()
                    if user_id in session.participants
                ]
                return JSONResponse(content={"sessions": user_sessions})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/ai/suggestions")
        async def get_smart_suggestions(user_id: str = "default", context: str = "{}"):
            """Get smart suggestions."""
            try:
                import json
                context_dict = json.loads(context)
                suggestions = await self.ai_integration.generate_smart_suggestions(user_id, context_dict)
                return JSONResponse(content={"suggestions": suggestions})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        # Enhanced API integration routes
        @self.router.get("/api/user/activity")
        async def get_user_activity(user_id: str = "default"):
            """Get user activity from API."""
            try:
                if not self.api_integration:
                    raise HTTPException(status_code=503, detail="API integration not available")

                from plugins.api_integration_layer.main import APIRequest
                request = APIRequest(endpoint="/users/activity", method="GET")
                result = await self.api_integration.make_api_request(request)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/api/messages/history")
        async def get_message_history(limit: int = 50):
            """Get message history."""
            try:
                if not self.api_integration:
                    raise HTTPException(status_code=503, detail="API integration not available")

                from plugins.api_integration_layer.main import APIRequest
                request = APIRequest(
                    endpoint="/messages/history",
                    method="GET",
                    params={"limit": str(limit)}
                )
                result = await self.api_integration.make_api_request(request)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/api/performance/dashboard")
        async def get_performance_dashboard():
            """Get performance dashboard data."""
            try:
                if not self.api_integration:
                    raise HTTPException(status_code=503, detail="API integration not available")

                from plugins.api_integration_layer.main import APIRequest
                request = APIRequest(endpoint="/performance/dashboard/data", method="GET")
                result = await self.api_integration.make_api_request(request)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/api/ai/usage")
        async def get_ai_usage():
            """Get AI usage analytics."""
            try:
                if not self.api_integration:
                    raise HTTPException(status_code=503, detail="API integration not available")

                from plugins.api_integration_layer.main import APIRequest
                request = APIRequest(endpoint="/ai/analytics/usage", method="GET")
                result = await self.api_integration.make_api_request(request)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/api/files/share")
        async def share_file(file_id: str, recipient_id: str, permissions: str = "read"):
            """Share a file with another user."""
            try:
                if not self.api_integration:
                    raise HTTPException(status_code=503, detail="API integration not available")

                from plugins.api_integration_layer.main import APIRequest
                request = APIRequest(
                    endpoint="/files/share",
                    method="POST",
                    data={
                        "file_id": file_id,
                        "recipient_id": recipient_id,
                        "permissions": permissions
                    }
                )
                result = await self.api_integration.make_api_request(request)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/api/collaboration/stats")
        async def get_collaboration_stats():
            """Get collaboration statistics."""
            try:
                if not self.api_integration:
                    raise HTTPException(status_code=503, detail="API integration not available")

                from plugins.api_integration_layer.main import APIRequest
                request = APIRequest(endpoint="/collaboration/stats", method="GET")
                result = await self.api_integration.make_api_request(request)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/api/backup/schedule")
        async def schedule_backup(name: str, schedule: str, backup_type: str = "incremental"):
            """Schedule a backup."""
            try:
                if not self.api_integration:
                    raise HTTPException(status_code=503, detail="API integration not available")

                from plugins.api_integration_layer.main import APIRequest
                request = APIRequest(
                    endpoint="/backup/create",
                    method="POST",
                    data={
                        "name": name,
                        "backup_type": backup_type,
                        "schedule": schedule
                    }
                )
                result = await self.api_integration.make_api_request(request)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/api/analytics/trends")
        async def get_analytics_trends(metric: str = "usage", period: str = "7d"):
            """Get analytics trends."""
            try:
                if not self.api_integration:
                    raise HTTPException(status_code=503, detail="API integration not available")

                from plugins.api_integration_layer.main import APIRequest
                request = APIRequest(
                    endpoint="/analytics/trends",
                    method="GET",
                    params={"metric": metric, "period": period}
                )
                result = await self.api_integration.make_api_request(request)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

    def _setup_websockets(self):
        """Setup WebSocket endpoints."""

        @self.router.websocket("/ws/collaboration/{session_id}")
        async def collaboration_websocket(websocket: WebSocket, session_id: str, user_id: str = "default"):
            """WebSocket for real-time collaboration."""
            try:
                await self.connection_manager.connect(websocket, user_id, session_id)
                self.connection_manager.join_room(session_id, f"collab_{session_id}")

                # Notify others of user joining
                await self.connection_manager.broadcast_to_room(
                    json.dumps({
                        "type": "user_joined",
                        "user_id": user_id,
                        "timestamp": datetime.now().isoformat()
                    }),
                    f"collab_{session_id}"
                )

                try:
                    while True:
                        data = await websocket.receive_text()
                        message_data = json.loads(data)

                        # Broadcast message to room
                        await self.connection_manager.broadcast_to_room(
                            json.dumps({
                                "type": "message",
                                "user_id": user_id,
                                "content": message_data.get("content"),
                                "timestamp": datetime.now().isoformat()
                            }),
                            f"collab_{session_id}"
                        )

                        # Track user action
                        if self.analytics:
                            await self.analytics.track_user_action(user_id, "collaboration_message", {
                                "session_id": session_id,
                                "message_length": len(message_data.get("content", ""))
                            })

                except WebSocketDisconnect:
                    pass
                finally:
                    self.connection_manager.disconnect(session_id, user_id)
                    self.connection_manager.leave_room(session_id, f"collab_{session_id}")

                    # Notify others of user leaving
                    await self.connection_manager.broadcast_to_room(
                        json.dumps({
                            "type": "user_left",
                            "user_id": user_id,
                            "timestamp": datetime.now().isoformat()
                        }),
                        f"collab_{session_id}"
                    )

            except Exception as e:
                logger.error(f"WebSocket error: {e}")

        @self.router.websocket("/ws/ai-chat/{user_id}")
        async def ai_chat_websocket(websocket: WebSocket, user_id: str):
            """WebSocket for AI chat."""
            try:
                session_id = str(uuid.uuid4())
                await self.connection_manager.connect(websocket, user_id, session_id)

                try:
                    while True:
                        data = await websocket.receive_text()
                        message_data = json.loads(data)

                        # Process AI request
                        ai_response = await self.ai_integration.process_chat_message(
                            message_data.get("message", ""), user_id, message_data.get("context")
                        )

                        # Send AI response
                        await websocket.send_text(json.dumps({
                            "type": "ai_response",
                            "response": ai_response["response"],
                            "confidence": ai_response.get("confidence", 0.0),
                            "timestamp": datetime.now().isoformat()
                        }))

                        # Track user action
                        if self.analytics:
                            await self.analytics.track_user_action(user_id, "ai_chat_ws", {
                                "message_length": len(message_data.get("message", ""))
                            })

                except WebSocketDisconnect:
                    pass
                finally:
                    self.connection_manager.disconnect(session_id, user_id)

            except Exception as e:
                logger.error(f"AI Chat WebSocket error: {e}")

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
                app.mount(f"/plugins/advanced-client/static",
                         StaticFiles(directory=str(ui_dir / "static")),
                         name="advanced_client_static")

    async def _start_background_tasks(self):
        """Start background tasks."""
        # Start analytics processing
        asyncio.create_task(self._analytics_processor())

        # Start AI model warming
        asyncio.create_task(self._warm_ai_models())

        # Start session cleanup
        asyncio.create_task(self._session_cleanup())

    async def _analytics_processor(self):
        """Background analytics processing."""
        while True:
            try:
                # Process analytics data every 5 minutes
                await asyncio.sleep(300)

                if self.analytics and hasattr(self.analytics, 'user_data'):
                    for user_id in self.analytics.user_data.keys():
                        insights = await self.analytics.generate_insights(user_id)
                    # Store insights or send notifications if needed

            except Exception as e:
                logger.error(f"Analytics processor error: {e}")
                await asyncio.sleep(60)

    async def _warm_ai_models(self):
        """Warm up AI models for better performance."""
        try:
            # Simulate model warming
            await self.ai_integration.process_chat_message(
                "Hello", "system", {"warmup": True}
            )
            logger.info("AI models warmed up successfully")
        except Exception as e:
            logger.error(f"Error warming AI models: {e}")

    async def _session_cleanup(self):
        """Clean up inactive sessions."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour

                current_time = datetime.now()
                inactive_sessions = []

                for session_id, session in self.active_sessions.items():
                    last_activity = datetime.fromisoformat(session.last_activity)
                    if current_time - last_activity > timedelta(hours=24):
                        inactive_sessions.append(session_id)

                for session_id in inactive_sessions:
                    del self.active_sessions[session_id]
                    logger.info(f"Cleaned up inactive session: {session_id}")

            except Exception as e:
                logger.error(f"Session cleanup error: {e}")

    # Self-test methods
    async def test_ai_integration(self) -> Dict[str, Any]:
        """Test AI integration functionality."""
        try:
            response = await self.ai_integration.process_chat_message(
                "Hello, this is a test", "test_user"
            )

            if not response.get("response"):
                return {"success": False, "error": "AI integration failed"}

            return {"success": True, "message": "AI integration test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_collaboration(self) -> Dict[str, Any]:
        """Test collaboration functionality."""
        try:
            # Test session creation
            session_id = str(uuid.uuid4())
            session = CollaborationSession(
                session_id=session_id,
                workspace_id="test_workspace",
                participants=["test_user"],
                created_at=datetime.now().isoformat(),
                last_activity=datetime.now().isoformat()
            )

            self.active_sessions[session_id] = session

            if session_id not in self.active_sessions:
                return {"success": False, "error": "Session creation failed"}

            # Cleanup
            del self.active_sessions[session_id]

            return {"success": True, "message": "Collaboration test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_voice_features(self) -> Dict[str, Any]:
        """Test voice features."""
        try:
            # Test voice processing
            result = await self.voice_processor.process_voice_command(b"test_audio", "test_user")

            if "error" in result and "disabled" not in result["error"]:
                return {"success": False, "error": "Voice processing failed"}

            return {"success": True, "message": "Voice features test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_ui_components(self) -> Dict[str, Any]:
        """Test UI components."""
        try:
            # Test that UI configuration is valid
            ui_config = self.config.get('ui_theme', {})
            required_fields = ['mode', 'primary_color', 'accent_color']

            for field in required_fields:
                if field not in ui_config:
                    return {"success": False, "error": f"Missing UI config field: {field}"}

            return {"success": True, "message": "UI components test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_analytics(self) -> Dict[str, Any]:
        """Test analytics functionality."""
        try:
            # Test action tracking
            if self.analytics:
                await self.analytics.track_user_action("test_user", "test_action", {"test": True})

                # Test insights generation
                insights = await self.analytics.generate_insights("test_user")
            else:
                insights = {"total_actions": 0}

            if "total_actions" not in insights:
                return {"success": False, "error": "Analytics insights generation failed"}

            return {"success": True, "message": "Analytics test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_automation(self) -> Dict[str, Any]:
        """Test automation features."""
        try:
            # Test smart suggestions
            suggestions = await self.ai_integration.generate_smart_suggestions(
                "test_user", {"current_page": "dashboard"}
            )

            if not isinstance(suggestions, list):
                return {"success": False, "error": "Smart suggestions failed"}

            return {"success": True, "message": "Automation test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_websockets(self) -> Dict[str, Any]:
        """Test WebSocket functionality."""
        try:
            # Test connection manager
            manager = ConnectionManager()

            # Test room management
            manager.join_room("test_session", "test_room")
            manager.leave_room("test_session", "test_room")

            return {"success": True, "message": "WebSocket test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_performance(self) -> Dict[str, Any]:
        """Test performance metrics."""
        try:
            start_time = time.time()

            # Test AI response time
            await self.ai_integration.process_chat_message("Performance test", "test_user")

            response_time = time.time() - start_time

            if response_time > 5.0:  # 5 second threshold
                return {"success": False, "error": f"Performance too slow: {response_time:.2f}s"}

            return {"success": True, "message": f"Performance test passed ({response_time:.2f}s)"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def run_tests(self) -> Dict[str, Any]:
        """Run all plugin self-tests."""
        tests = [
            ("ai_integration", self.test_ai_integration),
            ("collaboration", self.test_collaboration),
            ("voice_features", self.test_voice_features),
            ("ui_components", self.test_ui_components),
            ("analytics", self.test_analytics),
            ("automation", self.test_automation),
            ("websockets", self.test_websockets),
            ("performance", self.test_performance)
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
    return AdvancedClientPlugin()
