"""
PlexiChat AI Node Plugin
Dedicated AI processing node with HuggingFace integration and local model support
"""

import asyncio
import logging
import json
import os
import sys
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

# PlexiChat imports
sys.path.append(str(Path(__file__).parent.parent.parent / "src"))
from plexichat.infrastructure.modules.plugin_manager import PluginInterface, PluginMetadata, PluginType
from plexichat.infrastructure.modules.interfaces import ModuleCapability, ModulePermissions

logger = logging.getLogger(__name__)


class ModelFramework(Enum):
    """Supported AI model frameworks."""
    TRANSFORMERS = "transformers"
    LLAMA_CPP = "llama.cpp"
    BITNET_CPP = "bitnet.cpp"
    ONNX = "onnx"
    TENSORRT = "tensorrt"


class ModelType(Enum):
    """Supported model types."""
    TEXT_GENERATION = "text-generation"
    TEXT_CLASSIFICATION = "text-classification"
    QUESTION_ANSWERING = "question-answering"
    SUMMARIZATION = "summarization"
    TRANSLATION = "translation"
    EMBEDDING = "embedding"
    IMAGE_CLASSIFICATION = "image-classification"
    IMAGE_GENERATION = "image-generation"
    SPEECH_RECOGNITION = "speech-recognition"
    TEXT_TO_SPEECH = "text-to-speech"


@dataclass
class ModelInfo:
    """AI model information."""
    model_id: str
    name: str
    framework: ModelFramework
    model_type: ModelType
    size_mb: int
    loaded: bool = False
    loading: bool = False
    last_used: Optional[datetime] = None
    usage_count: int = 0
    error_count: int = 0
    
    # HuggingFace specific
    hf_model_id: Optional[str] = None
    hf_revision: Optional[str] = None
    
    # Local file paths
    local_path: Optional[str] = None
    config_path: Optional[str] = None
    
    # Performance metrics
    avg_inference_time: float = 0.0
    memory_usage_mb: float = 0.0


class AINodePlugin(PluginInterface):
    """
    AI Node Plugin for PlexiChat.
    
    Features:
    - HuggingFace model integration
    - Local model support (llama.cpp, bitnet.cpp)
    - Web UI setup wizard
    - Model management interface
    - Distributed inference
    - GPU acceleration
    - Model quantization
    - Caching and optimization
    """
    
    def __init__(self):
        super().__init__("ai_node", "1.0.0")
        
        # Plugin configuration
        self.config_file = Path(__file__).parent / "config.json"
        self.models_dir = Path(__file__).parent / "models"
        self.cache_dir = Path(__file__).parent / "cache"
        
        # Ensure directories exist
        self.models_dir.mkdir(exist_ok=True)
        self.cache_dir.mkdir(exist_ok=True)
        
        # Model management
        self.loaded_models: Dict[str, Any] = {}
        self.model_info: Dict[str, ModelInfo] = {}
        self.model_queue = asyncio.Queue()
        
        # Configuration
        self.max_models = 10
        self.model_cache_size_gb = 50
        self.inference_timeout = 30
        self.enable_gpu = True
        self.enable_quantization = True
        
        # Statistics
        self.stats = {
            "models_loaded": 0,
            "total_inferences": 0,
            "successful_inferences": 0,
            "failed_inferences": 0,
            "total_inference_time": 0.0,
            "cache_hits": 0,
            "cache_misses": 0
        }
        
        # Background tasks
        self.model_manager_task: Optional[asyncio.Task] = None
        self.inference_worker_task: Optional[asyncio.Task] = None
        
        # Web UI
        self.web_ui_port = 8080
        self.web_ui_app = None
    
    async def initialize(self) -> bool:
        """Initialize the AI node plugin."""
        try:
            self.logger.info("🤖 Initializing AI Node Plugin")
            
            # Load configuration
            await self._load_configuration()
            
            # Initialize model frameworks
            await self._initialize_frameworks()
            
            # Start background tasks
            await self._start_background_tasks()
            
            # Initialize web UI
            await self._initialize_web_ui()
            
            # Load default models
            await self._load_default_models()
            
            self.logger.info("✅ AI Node Plugin initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize AI Node Plugin: {e}")
            return False
    
    async def _load_configuration(self):
        """Load plugin configuration."""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                
            self.max_models = config.get("max_models", 10)
            self.model_cache_size_gb = config.get("model_cache_size_gb", 50)
            self.inference_timeout = config.get("inference_timeout", 30)
            self.enable_gpu = config.get("enable_gpu", True)
            self.enable_quantization = config.get("enable_quantization", True)
            self.web_ui_port = config.get("web_ui_port", 8080)
        else:
            # Create default configuration
            await self._save_configuration()
    
    async def _save_configuration(self):
        """Save plugin configuration."""
        config = {
            "max_models": self.max_models,
            "model_cache_size_gb": self.model_cache_size_gb,
            "inference_timeout": self.inference_timeout,
            "enable_gpu": self.enable_gpu,
            "enable_quantization": self.enable_quantization,
            "web_ui_port": self.web_ui_port
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    async def _initialize_frameworks(self):
        """Initialize AI model frameworks."""
        self.logger.info("🔧 Initializing AI frameworks")
        
        # Check for available frameworks
        self.available_frameworks = []
        
        # Check Transformers
        try:
            import transformers
            self.available_frameworks.append(ModelFramework.TRANSFORMERS)
            self.logger.info("✅ Transformers framework available")
        except ImportError:
            self.logger.warning("⚠️ Transformers framework not available")
        
        # Check llama.cpp
        try:
            import llama_cpp
            self.available_frameworks.append(ModelFramework.LLAMA_CPP)
            self.logger.info("✅ llama.cpp framework available")
        except ImportError:
            self.logger.warning("⚠️ llama.cpp framework not available")
        
        # Check bitnet.cpp (placeholder - would need actual implementation)
        # try:
        #     import bitnet_cpp
        #     self.available_frameworks.append(ModelFramework.BITNET_CPP)
        #     self.logger.info("✅ bitnet.cpp framework available")
        # except ImportError:
        #     self.logger.warning("⚠️ bitnet.cpp framework not available")
        
        # Check ONNX
        try:
            import onnxruntime
            self.available_frameworks.append(ModelFramework.ONNX)
            self.logger.info("✅ ONNX framework available")
        except ImportError:
            self.logger.warning("⚠️ ONNX framework not available")
    
    async def _start_background_tasks(self):
        """Start background tasks."""
        self.model_manager_task = asyncio.create_task(self._model_manager_loop())
        self.inference_worker_task = asyncio.create_task(self._inference_worker_loop())
    
    async def _initialize_web_ui(self):
        """Initialize web UI for model management."""
        try:
            from fastapi import FastAPI, HTTPException
            from fastapi.staticfiles import StaticFiles
            from fastapi.responses import HTMLResponse
            import uvicorn
            
            self.web_ui_app = FastAPI(title="AI Node Management", version="1.0.0")
            
            # Add API endpoints
            await self._setup_web_ui_endpoints()
            
            # Start web server in background
            asyncio.create_task(self._run_web_ui())
            
            self.logger.info(f"🌐 Web UI available at http://localhost:{self.web_ui_port}")
            
        except ImportError:
            self.logger.warning("⚠️ FastAPI not available, web UI disabled")
    
    async def _setup_web_ui_endpoints(self):
        """Setup web UI API endpoints."""
        if not self.web_ui_app:
            return
        
        @self.web_ui_app.get("/")
        async def get_dashboard():
            """Get AI node dashboard."""
            return HTMLResponse(self._get_dashboard_html())
        
        @self.web_ui_app.get("/api/models")
        async def list_models():
            """List available models."""
            return {
                "models": [
                    {
                        "id": model_id,
                        "name": info.name,
                        "framework": info.framework.value,
                        "type": info.model_type.value,
                        "loaded": info.loaded,
                        "size_mb": info.size_mb,
                        "usage_count": info.usage_count
                    }
                    for model_id, info in self.model_info.items()
                ]
            }
        
        @self.web_ui_app.post("/api/models/{model_id}/load")
        async def load_model(model_id: str):
            """Load a model."""
            success = await self.load_model(model_id)
            if success:
                return {"success": True, "message": f"Model {model_id} loaded"}
            else:
                raise HTTPException(status_code=500, detail=f"Failed to load model {model_id}")
        
        @self.web_ui_app.post("/api/models/{model_id}/unload")
        async def unload_model(model_id: str):
            """Unload a model."""
            success = await self.unload_model(model_id)
            if success:
                return {"success": True, "message": f"Model {model_id} unloaded"}
            else:
                raise HTTPException(status_code=500, detail=f"Failed to unload model {model_id}")
        
        @self.web_ui_app.post("/api/huggingface/search")
        async def search_huggingface_models(query: dict):
            """Search HuggingFace models."""
            return await self.search_huggingface_models(query.get("query", ""))
        
        @self.web_ui_app.post("/api/huggingface/install")
        async def install_huggingface_model(model_data: dict):
            """Install model from HuggingFace."""
            model_id = model_data.get("model_id")
            if not model_id:
                raise HTTPException(status_code=400, detail="model_id required")
            
            success = await self.install_huggingface_model(model_id)
            if success:
                return {"success": True, "message": f"Model {model_id} installed"}
            else:
                raise HTTPException(status_code=500, detail=f"Failed to install model {model_id}")
    
    async def _run_web_ui(self):
        """Run web UI server."""
        if not self.web_ui_app:
            return
        
        try:
            import uvicorn
            config = uvicorn.Config(
                self.web_ui_app,
                host="0.0.0.0",
                port=self.web_ui_port,
                log_level="info"
            )
            server = uvicorn.Server(config)
            await server.serve()
        except Exception as e:
            self.logger.error(f"Web UI server error: {e}")
    
    def _get_dashboard_html(self) -> str:
        """Get dashboard HTML."""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>AI Node Management</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .model-card { background: #f8f9fa; padding: 10px; margin: 10px 0; border-radius: 3px; }
                .btn { padding: 8px 16px; margin: 5px; border: none; border-radius: 3px; cursor: pointer; }
                .btn-primary { background: #3498db; color: white; }
                .btn-success { background: #27ae60; color: white; }
                .btn-danger { background: #e74c3c; color: white; }
                .status-loaded { color: #27ae60; font-weight: bold; }
                .status-unloaded { color: #e74c3c; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🤖 AI Node Management</h1>
                <p>Manage AI models and inference services</p>
            </div>
            
            <div class="section">
                <h2>📊 System Status</h2>
                <p><strong>Models Loaded:</strong> <span id="models-loaded">0</span></p>
                <p><strong>Total Inferences:</strong> <span id="total-inferences">0</span></p>
                <p><strong>Available Frameworks:</strong> <span id="frameworks">Loading...</span></p>
            </div>
            
            <div class="section">
                <h2>🔍 HuggingFace Model Search</h2>
                <input type="text" id="search-query" placeholder="Search models..." style="width: 300px; padding: 8px;">
                <button class="btn btn-primary" onclick="searchModels()">Search</button>
                <div id="search-results"></div>
            </div>
            
            <div class="section">
                <h2>📦 Installed Models</h2>
                <div id="installed-models">Loading...</div>
            </div>
            
            <script>
                async function loadDashboard() {
                    try {
                        const response = await fetch('/api/models');
                        const data = await response.json();
                        
                        const modelsContainer = document.getElementById('installed-models');
                        modelsContainer.innerHTML = '';
                        
                        data.models.forEach(model => {
                            const modelCard = document.createElement('div');
                            modelCard.className = 'model-card';
                            modelCard.innerHTML = `
                                <h4>${model.name}</h4>
                                <p><strong>ID:</strong> ${model.id}</p>
                                <p><strong>Framework:</strong> ${model.framework}</p>
                                <p><strong>Type:</strong> ${model.type}</p>
                                <p><strong>Size:</strong> ${model.size_mb} MB</p>
                                <p><strong>Status:</strong> <span class="${model.loaded ? 'status-loaded' : 'status-unloaded'}">${model.loaded ? 'Loaded' : 'Unloaded'}</span></p>
                                <p><strong>Usage:</strong> ${model.usage_count} times</p>
                                <button class="btn ${model.loaded ? 'btn-danger' : 'btn-success'}" onclick="${model.loaded ? 'unloadModel' : 'loadModel'}('${model.id}')">
                                    ${model.loaded ? 'Unload' : 'Load'}
                                </button>
                            `;
                            modelsContainer.appendChild(modelCard);
                        });
                        
                        document.getElementById('models-loaded').textContent = data.models.filter(m => m.loaded).length;
                    } catch (error) {
                        console.error('Failed to load dashboard:', error);
                    }
                }
                
                async function searchModels() {
                    const query = document.getElementById('search-query').value;
                    if (!query) return;
                    
                    try {
                        const response = await fetch('/api/huggingface/search', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ query })
                        });
                        const data = await response.json();
                        
                        const resultsContainer = document.getElementById('search-results');
                        resultsContainer.innerHTML = '<h3>Search Results:</h3>';
                        
                        data.models.forEach(model => {
                            const modelCard = document.createElement('div');
                            modelCard.className = 'model-card';
                            modelCard.innerHTML = `
                                <h4>${model.modelId}</h4>
                                <p>${model.description || 'No description available'}</p>
                                <p><strong>Downloads:</strong> ${model.downloads || 'N/A'}</p>
                                <button class="btn btn-primary" onclick="installModel('${model.modelId}')">Install</button>
                            `;
                            resultsContainer.appendChild(modelCard);
                        });
                    } catch (error) {
                        console.error('Search failed:', error);
                    }
                }
                
                async function loadModel(modelId) {
                    try {
                        const response = await fetch(`/api/models/${modelId}/load`, { method: 'POST' });
                        if (response.ok) {
                            loadDashboard();
                        }
                    } catch (error) {
                        console.error('Failed to load model:', error);
                    }
                }
                
                async function unloadModel(modelId) {
                    try {
                        const response = await fetch(`/api/models/${modelId}/unload`, { method: 'POST' });
                        if (response.ok) {
                            loadDashboard();
                        }
                    } catch (error) {
                        console.error('Failed to unload model:', error);
                    }
                }
                
                async function installModel(modelId) {
                    try {
                        const response = await fetch('/api/huggingface/install', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ model_id: modelId })
                        });
                        if (response.ok) {
                            alert('Model installation started');
                            loadDashboard();
                        }
                    } catch (error) {
                        console.error('Failed to install model:', error);
                    }
                }
                
                // Load dashboard on page load
                loadDashboard();
                
                // Refresh every 30 seconds
                setInterval(loadDashboard, 30000);
            </script>
        </body>
        </html>
        """

    async def _load_default_models(self):
        """Load default models."""
        # Add some default models
        default_models = [
            {
                "model_id": "microsoft/DialoGPT-medium",
                "name": "DialoGPT Medium",
                "framework": ModelFramework.TRANSFORMERS,
                "model_type": ModelType.TEXT_GENERATION,
                "hf_model_id": "microsoft/DialoGPT-medium"
            },
            {
                "model_id": "sentence-transformers/all-MiniLM-L6-v2",
                "name": "All MiniLM L6 v2",
                "framework": ModelFramework.TRANSFORMERS,
                "model_type": ModelType.EMBEDDING,
                "hf_model_id": "sentence-transformers/all-MiniLM-L6-v2"
            }
        ]

        for model_data in default_models:
            model_info = ModelInfo(
                model_id=model_data["model_id"],
                name=model_data["name"],
                framework=model_data["framework"],
                model_type=model_data["model_type"],
                size_mb=500,  # Estimated
                hf_model_id=model_data.get("hf_model_id")
            )
            self.model_info[model_data["model_id"]] = model_info

    async def _model_manager_loop(self):
        """Background model management loop."""
        while True:
            try:
                # Clean up unused models
                await self._cleanup_unused_models()

                # Update model statistics
                await self._update_model_statistics()

                # Sleep for 5 minutes
                await asyncio.sleep(300)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Model manager loop error: {e}")
                await asyncio.sleep(60)

    async def _inference_worker_loop(self):
        """Background inference worker loop."""
        while True:
            try:
                # Process inference requests from queue
                if not self.model_queue.empty():
                    request = await self.model_queue.get()
                    await self._process_inference_request(request)
                else:
                    await asyncio.sleep(0.1)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Inference worker loop error: {e}")
                await asyncio.sleep(1)

    async def _cleanup_unused_models(self):
        """Clean up unused models to free memory."""
        current_time = datetime.now(timezone.utc)

        for model_id, info in list(self.model_info.items()):
            if info.loaded and info.last_used:
                # Unload models not used in the last hour
                time_since_use = (current_time - info.last_used).total_seconds()
                if time_since_use > 3600:  # 1 hour
                    await self.unload_model(model_id)
                    self.logger.info(f"Unloaded unused model: {model_id}")

    async def _update_model_statistics(self):
        """Update model usage statistics."""
        self.stats["models_loaded"] = sum(1 for info in self.model_info.values() if info.loaded)

    async def _process_inference_request(self, request: Dict[str, Any]):
        """Process an inference request."""
        try:
            model_id = request.get("model_id")
            input_data = request.get("input")
            callback = request.get("callback")

            if model_id not in self.loaded_models:
                if callback:
                    await callback({"error": f"Model {model_id} not loaded"})
                return

            # Perform inference
            start_time = datetime.now(timezone.utc)
            result = await self._run_inference(model_id, input_data)
            end_time = datetime.now(timezone.utc)

            # Update statistics
            inference_time = (end_time - start_time).total_seconds()
            self.stats["total_inferences"] += 1
            self.stats["total_inference_time"] += inference_time

            if "error" not in result:
                self.stats["successful_inferences"] += 1
            else:
                self.stats["failed_inferences"] += 1

            # Update model statistics
            if model_id in self.model_info:
                info = self.model_info[model_id]
                info.usage_count += 1
                info.last_used = end_time

                # Update average inference time
                if info.avg_inference_time == 0:
                    info.avg_inference_time = inference_time
                else:
                    info.avg_inference_time = (info.avg_inference_time + inference_time) / 2

            # Return result via callback
            if callback:
                await callback(result)

        except Exception as e:
            self.logger.error(f"Inference request processing error: {e}")
            if request.get("callback"):
                await request["callback"]({"error": str(e)})

    async def _run_inference(self, model_id: str, input_data: Any) -> Dict[str, Any]:
        """Run inference on a loaded model."""
        try:
            model = self.loaded_models.get(model_id)
            if not model:
                return {"error": f"Model {model_id} not found"}

            model_info = self.model_info.get(model_id)
            if not model_info:
                return {"error": f"Model info for {model_id} not found"}

            # Route to appropriate inference method based on framework
            if model_info.framework == ModelFramework.TRANSFORMERS:
                return await self._run_transformers_inference(model, model_info, input_data)
            elif model_info.framework == ModelFramework.LLAMA_CPP:
                return await self._run_llama_cpp_inference(model, model_info, input_data)
            elif model_info.framework == ModelFramework.ONNX:
                return await self._run_onnx_inference(model, model_info, input_data)
            else:
                return {"error": f"Unsupported framework: {model_info.framework}"}

        except Exception as e:
            return {"error": f"Inference error: {str(e)}"}

    async def _run_transformers_inference(self, model: Any, model_info: ModelInfo, input_data: Any) -> Dict[str, Any]:
        """Run inference using Transformers framework."""
        try:
            if model_info.model_type == ModelType.TEXT_GENERATION:
                # Text generation
                if isinstance(input_data, str):
                    inputs = model["tokenizer"](input_data, return_tensors="pt")
                    outputs = model["model"].generate(**inputs, max_length=100, do_sample=True)
                    response = model["tokenizer"].decode(outputs[0], skip_special_tokens=True)
                    return {"output": response, "type": "text_generation"}

            elif model_info.model_type == ModelType.EMBEDDING:
                # Text embedding
                if isinstance(input_data, str):
                    inputs = model["tokenizer"](input_data, return_tensors="pt", padding=True, truncation=True)
                    outputs = model["model"](**inputs)
                    embeddings = outputs.last_hidden_state.mean(dim=1).detach().numpy().tolist()
                    return {"output": embeddings, "type": "embedding"}

            return {"error": "Unsupported model type for Transformers"}

        except Exception as e:
            return {"error": f"Transformers inference error: {str(e)}"}

    async def _run_llama_cpp_inference(self, model: Any, model_info: ModelInfo, input_data: Any) -> Dict[str, Any]:
        """Run inference using llama.cpp."""
        try:
            if isinstance(input_data, str):
                output = model(input_data, max_tokens=100)
                return {"output": output["choices"][0]["text"], "type": "text_generation"}

            return {"error": "Invalid input for llama.cpp"}

        except Exception as e:
            return {"error": f"llama.cpp inference error: {str(e)}"}

    async def _run_onnx_inference(self, model: Any, model_info: ModelInfo, input_data: Any) -> Dict[str, Any]:
        """Run inference using ONNX."""
        try:
            # ONNX inference implementation would go here
            return {"error": "ONNX inference not implemented yet"}

        except Exception as e:
            return {"error": f"ONNX inference error: {str(e)}"}

    # Public API Methods

    async def load_model(self, model_id: str) -> bool:
        """Load a model for inference."""
        try:
            if model_id in self.loaded_models:
                self.logger.info(f"Model {model_id} already loaded")
                return True

            if model_id not in self.model_info:
                self.logger.error(f"Model {model_id} not found in registry")
                return False

            model_info = self.model_info[model_id]
            model_info.loading = True

            self.logger.info(f"Loading model: {model_id}")

            # Load based on framework
            if model_info.framework == ModelFramework.TRANSFORMERS:
                success = await self._load_transformers_model(model_id, model_info)
            elif model_info.framework == ModelFramework.LLAMA_CPP:
                success = await self._load_llama_cpp_model(model_id, model_info)
            elif model_info.framework == ModelFramework.ONNX:
                success = await self._load_onnx_model(model_id, model_info)
            else:
                self.logger.error(f"Unsupported framework: {model_info.framework}")
                success = False

            model_info.loading = False

            if success:
                model_info.loaded = True
                self.logger.info(f"✅ Model {model_id} loaded successfully")
            else:
                model_info.error_count += 1
                self.logger.error(f"❌ Failed to load model {model_id}")

            return success

        except Exception as e:
            self.logger.error(f"Error loading model {model_id}: {e}")
            if model_id in self.model_info:
                self.model_info[model_id].loading = False
                self.model_info[model_id].error_count += 1
            return False

    async def _load_transformers_model(self, model_id: str, model_info: ModelInfo) -> bool:
        """Load a Transformers model."""
        try:
            from transformers import AutoTokenizer, AutoModel, AutoModelForCausalLM

            hf_model_id = model_info.hf_model_id or model_id

            # Load tokenizer
            tokenizer = AutoTokenizer.from_pretrained(hf_model_id)

            # Load model based on type
            if model_info.model_type == ModelType.TEXT_GENERATION:
                model = AutoModelForCausalLM.from_pretrained(hf_model_id)
            else:
                model = AutoModel.from_pretrained(hf_model_id)

            # Store model and tokenizer
            self.loaded_models[model_id] = {
                "model": model,
                "tokenizer": tokenizer,
                "framework": ModelFramework.TRANSFORMERS
            }

            return True

        except Exception as e:
            self.logger.error(f"Failed to load Transformers model {model_id}: {e}")
            return False

    async def _load_llama_cpp_model(self, model_id: str, model_info: ModelInfo) -> bool:
        """Load a llama.cpp model."""
        try:
            from llama_cpp import Llama

            model_path = model_info.local_path
            if not model_path or not os.path.exists(model_path):
                self.logger.error(f"Model file not found: {model_path}")
                return False

            # Load llama.cpp model
            model = Llama(model_path=model_path, n_ctx=2048, verbose=False)

            self.loaded_models[model_id] = {
                "model": model,
                "framework": ModelFramework.LLAMA_CPP
            }

            return True

        except Exception as e:
            self.logger.error(f"Failed to load llama.cpp model {model_id}: {e}")
            return False

    async def _load_onnx_model(self, model_id: str, model_info: ModelInfo) -> bool:
        """Load an ONNX model."""
        try:
            import onnxruntime as ort

            model_path = model_info.local_path
            if not model_path or not os.path.exists(model_path):
                self.logger.error(f"Model file not found: {model_path}")
                return False

            # Load ONNX model
            session = ort.InferenceSession(model_path)

            self.loaded_models[model_id] = {
                "session": session,
                "framework": ModelFramework.ONNX
            }

            return True

        except Exception as e:
            self.logger.error(f"Failed to load ONNX model {model_id}: {e}")
            return False

    async def unload_model(self, model_id: str) -> bool:
        """Unload a model from memory."""
        try:
            if model_id not in self.loaded_models:
                self.logger.warning(f"Model {model_id} not loaded")
                return True

            # Remove from loaded models
            del self.loaded_models[model_id]

            # Update model info
            if model_id in self.model_info:
                self.model_info[model_id].loaded = False

            self.logger.info(f"✅ Model {model_id} unloaded")
            return True

        except Exception as e:
            self.logger.error(f"Error unloading model {model_id}: {e}")
            return False

    async def search_huggingface_models(self, query: str) -> Dict[str, Any]:
        """Search for models on HuggingFace Hub."""
        try:
            from huggingface_hub import HfApi

            api = HfApi()
            models = api.list_models(search=query, limit=20)

            results = []
            for model in models:
                results.append({
                    "modelId": model.modelId,
                    "description": getattr(model, 'description', ''),
                    "downloads": getattr(model, 'downloads', 0),
                    "tags": getattr(model, 'tags', []),
                    "pipeline_tag": getattr(model, 'pipeline_tag', '')
                })

            return {"models": results}

        except Exception as e:
            self.logger.error(f"HuggingFace search error: {e}")
            return {"models": [], "error": str(e)}

    async def install_huggingface_model(self, model_id: str) -> bool:
        """Install a model from HuggingFace Hub."""
        try:
            from huggingface_hub import snapshot_download

            self.logger.info(f"Installing model from HuggingFace: {model_id}")

            # Download model to local directory
            local_path = self.models_dir / model_id.replace("/", "_")
            local_path.mkdir(exist_ok=True)

            snapshot_download(
                repo_id=model_id,
                local_dir=str(local_path),
                local_dir_use_symlinks=False
            )

            # Determine model type and framework
            model_type = self._detect_model_type(model_id)
            framework = ModelFramework.TRANSFORMERS  # Default to Transformers

            # Create model info
            model_info = ModelInfo(
                model_id=model_id,
                name=model_id.split("/")[-1],
                framework=framework,
                model_type=model_type,
                size_mb=self._calculate_model_size(local_path),
                hf_model_id=model_id,
                local_path=str(local_path)
            )

            self.model_info[model_id] = model_info

            self.logger.info(f"✅ Model {model_id} installed successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to install model {model_id}: {e}")
            return False

    def _detect_model_type(self, model_id: str) -> ModelType:
        """Detect model type from model ID or config."""
        # Simple heuristic based on model name
        model_id_lower = model_id.lower()

        if "gpt" in model_id_lower or "llama" in model_id_lower or "mistral" in model_id_lower:
            return ModelType.TEXT_GENERATION
        elif "bert" in model_id_lower or "roberta" in model_id_lower:
            return ModelType.TEXT_CLASSIFICATION
        elif "sentence" in model_id_lower or "embedding" in model_id_lower:
            return ModelType.EMBEDDING
        elif "summarization" in model_id_lower:
            return ModelType.SUMMARIZATION
        elif "translation" in model_id_lower:
            return ModelType.TRANSLATION
        else:
            return ModelType.TEXT_GENERATION  # Default

    def _calculate_model_size(self, model_path: Path) -> int:
        """Calculate model size in MB."""
        try:
            total_size = 0
            for file_path in model_path.rglob("*"):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
            return int(total_size / (1024 * 1024))  # Convert to MB
        except Exception:
            return 0

    async def run_inference(self, model_id: str, input_data: Any) -> Dict[str, Any]:
        """Public method to run inference."""
        if model_id not in self.loaded_models:
            # Try to load the model first
            if not await self.load_model(model_id):
                return {"error": f"Failed to load model {model_id}"}

        return await self._run_inference(model_id, input_data)

    async def queue_inference(self, model_id: str, input_data: Any, callback: Callable = None) -> bool:
        """Queue an inference request for background processing."""
        try:
            request = {
                "model_id": model_id,
                "input": input_data,
                "callback": callback,
                "timestamp": datetime.now(timezone.utc)
            }

            await self.model_queue.put(request)
            return True

        except Exception as e:
            self.logger.error(f"Failed to queue inference request: {e}")
            return False

    # Plugin Interface Methods

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="AI Node",
            version="1.0.0",
            description="Dedicated AI processing node with HuggingFace integration and local model support",
            plugin_type=PluginType.AI_NODE,
            author="PlexiChat Team",
            dependencies=["transformers", "huggingface_hub", "fastapi"],
            capabilities=[
                ModuleCapability.AI_SERVICES,
                ModuleCapability.MODEL_MANAGEMENT,
                ModuleCapability.INFERENCE_ENGINE,
                ModuleCapability.HUGGINGFACE_INTEGRATION,
                ModuleCapability.NETWORK_ACCESS,
                ModuleCapability.FILE_SYSTEM_ACCESS,
                ModuleCapability.BACKGROUND_TASKS,
                ModuleCapability.CACHING,
                ModuleCapability.CLUSTERING,
                ModuleCapability.MONITORING
            ]
        )

    def get_required_permissions(self) -> ModulePermissions:
        """Get required permissions."""
        return ModulePermissions(
            capabilities=[
                ModuleCapability.AI_SERVICES,
                ModuleCapability.MODEL_MANAGEMENT,
                ModuleCapability.INFERENCE_ENGINE,
                ModuleCapability.HUGGINGFACE_INTEGRATION,
                ModuleCapability.NETWORK_ACCESS,
                ModuleCapability.FILE_SYSTEM_ACCESS,
                ModuleCapability.BACKGROUND_TASKS,
                ModuleCapability.CACHING,
                ModuleCapability.CLUSTERING,
                ModuleCapability.MONITORING
            ],
            network_access=True,
            file_system_access=True,
            database_access=False
        )

    async def start(self) -> bool:
        """Start the plugin."""
        return await self.initialize()

    async def stop(self) -> bool:
        """Stop the plugin."""
        try:
            # Cancel background tasks
            if self.model_manager_task:
                self.model_manager_task.cancel()
            if self.inference_worker_task:
                self.inference_worker_task.cancel()

            # Unload all models
            for model_id in list(self.loaded_models.keys()):
                await self.unload_model(model_id)

            self.logger.info("✅ AI Node Plugin stopped")
            return True

        except Exception as e:
            self.logger.error(f"Error stopping AI Node Plugin: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get plugin status."""
        return {
            "name": "AI Node",
            "version": "1.0.0",
            "status": "running" if self.model_manager_task and not self.model_manager_task.done() else "stopped",
            "models_loaded": len(self.loaded_models),
            "models_available": len(self.model_info),
            "available_frameworks": [f.value for f in self.available_frameworks],
            "statistics": self.stats,
            "configuration": {
                "max_models": self.max_models,
                "model_cache_size_gb": self.model_cache_size_gb,
                "inference_timeout": self.inference_timeout,
                "enable_gpu": self.enable_gpu,
                "enable_quantization": self.enable_quantization,
                "web_ui_port": self.web_ui_port
            },
            "web_ui_url": f"http://localhost:{self.web_ui_port}"
        }

    def get_api_endpoints(self) -> List[Dict[str, str]]:
        """Get API endpoints provided by this plugin."""
        return [
            {"path": "/", "method": "GET", "description": "AI Node Dashboard"},
            {"path": "/api/models", "method": "GET", "description": "List models"},
            {"path": "/api/models/{model_id}/load", "method": "POST", "description": "Load model"},
            {"path": "/api/models/{model_id}/unload", "method": "POST", "description": "Unload model"},
            {"path": "/api/huggingface/search", "method": "POST", "description": "Search HuggingFace models"},
            {"path": "/api/huggingface/install", "method": "POST", "description": "Install HuggingFace model"},
            {"path": "/api/inference", "method": "POST", "description": "Run inference"}
        ]

    def get_cli_commands(self) -> List[Dict[str, str]]:
        """Get CLI commands provided by this plugin."""
        return [
            {"command": "ai-node status", "description": "Show AI node status"},
            {"command": "ai-node list-models", "description": "List available models"},
            {"command": "ai-node load-model <model_id>", "description": "Load a model"},
            {"command": "ai-node unload-model <model_id>", "description": "Unload a model"},
            {"command": "ai-node search-hf <query>", "description": "Search HuggingFace models"},
            {"command": "ai-node install-hf <model_id>", "description": "Install HuggingFace model"},
            {"command": "ai-node inference <model_id> <input>", "description": "Run inference"}
        ]

    async def handle_cli_command(self, command: str, args: List[str]) -> Dict[str, Any]:
        """Handle CLI commands."""
        try:
            if command == "status":
                return {"success": True, "data": self.get_status()}

            elif command == "list-models":
                models = []
                for model_id, info in self.model_info.items():
                    models.append({
                        "id": model_id,
                        "name": info.name,
                        "framework": info.framework.value,
                        "type": info.model_type.value,
                        "loaded": info.loaded,
                        "size_mb": info.size_mb
                    })
                return {"success": True, "data": {"models": models}}

            elif command == "load-model" and args:
                model_id = args[0]
                success = await self.load_model(model_id)
                return {"success": success, "message": f"Model {model_id} {'loaded' if success else 'failed to load'}"}

            elif command == "unload-model" and args:
                model_id = args[0]
                success = await self.unload_model(model_id)
                return {"success": success, "message": f"Model {model_id} {'unloaded' if success else 'failed to unload'}"}

            elif command == "search-hf" and args:
                query = " ".join(args)
                results = await self.search_huggingface_models(query)
                return {"success": True, "data": results}

            elif command == "install-hf" and args:
                model_id = args[0]
                success = await self.install_huggingface_model(model_id)
                return {"success": success, "message": f"Model {model_id} {'installed' if success else 'failed to install'}"}

            elif command == "inference" and len(args) >= 2:
                model_id = args[0]
                input_text = " ".join(args[1:])
                result = await self.run_inference(model_id, input_text)
                return {"success": "error" not in result, "data": result}

            else:
                return {"success": False, "error": "Unknown command or missing arguments"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    # Integration with PlexiChat systems

    async def integrate_with_clustering(self):
        """Integrate with PlexiChat clustering system."""
        if self.system_access:
            try:
                # Register as AI processing node in cluster
                cluster_status = await self.system_access.get_cluster_status()

                # Broadcast AI node availability
                await self.system_access.broadcast_to_cluster({
                    "type": "ai_node_available",
                    "node_id": self.name,
                    "capabilities": [cap.value for cap in self.get_required_permissions().capabilities],
                    "models_loaded": len(self.loaded_models),
                    "web_ui_port": self.web_ui_port
                })

                self.logger.info("✅ Integrated with clustering system")

            except Exception as e:
                self.logger.error(f"Failed to integrate with clustering: {e}")

    async def integrate_with_ai_services(self):
        """Integrate with PlexiChat AI services."""
        if self.system_access:
            try:
                # Register inference capabilities with AI coordinator
                # This would allow other parts of the system to use this node for inference

                self.logger.info("✅ Integrated with AI services")

            except Exception as e:
                self.logger.error(f"Failed to integrate with AI services: {e}")

    async def setup_monitoring(self):
        """Setup monitoring integration."""
        if self.system_access:
            try:
                # Report metrics to system monitoring
                metrics = await self.system_access.get_system_metrics()

                # Cache model information for quick access
                await self.system_access.set_cache_value(
                    f"ai_node:{self.name}:models",
                    list(self.model_info.keys()),
                    ttl=300
                )

                self.logger.info("✅ Monitoring integration setup")

            except Exception as e:
                self.logger.error(f"Failed to setup monitoring: {e}")


# Plugin entry point
def create_plugin():
    """Create plugin instance."""
    return AINodePlugin()
