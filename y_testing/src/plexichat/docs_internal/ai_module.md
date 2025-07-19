# PlexiChat AI Abstraction Layer

A comprehensive AI management system with multi-provider support, fallbacks, access control, and monitoring.

## Features

### 🤖 Multi-Provider Support
- **OpenAI**: GPT-4, GPT-3.5 Turbo with function calling
- **Anthropic**: Claude 3 (Opus, Sonnet, Haiku)
- **Google**: Gemini models
- **Cohere**: Command models
- **Hugging Face**: Open source models
- **Ollama**: Local model hosting
- **Azure OpenAI**: Enterprise OpenAI deployment
- **AWS Bedrock**: Amazon's AI service
- **Custom**: Support for custom endpoints

### 🔄 Intelligent Fallbacks
- Automatic fallback to secondary models on failure
- Configurable fallback chains per model
- Smart model selection based on capabilities
- Health monitoring and automatic failover

### 🔐 Access Control & Security
- Role-based permissions per user and model
- Granular capability-based access control
- Rate limiting per user and model
- Encrypted API key storage
- Admin user management

### 📊 Monitoring & Analytics
- Real-time health monitoring
- Usage tracking and cost analysis
- Performance metrics and latency monitoring
- Request/response history
- Model availability status

### 🚀 Performance Features
- Request caching for improved performance
- Streaming support for real-time responses
- Concurrent request handling
- Background health checks
- Automatic retry mechanisms

## Architecture

```
src/plexichat/ai/
├── core/
│   └── ai_abstraction_layer.py    # Main AI management system
├── api/
│   └── ai_endpoints.py            # REST API endpoints
├── webui/
│   ├── ai_management.py           # Web interface
│   └── templates/                 # HTML templates
├── cli/
│   └── ai_cli.py                  # Command-line interface
└── README.md                      # This file
```

## Quick Start

### 1. Configuration

Copy the example configuration:
```bash
cp config/ai_config_example.json config/ai_config.json
```

### 2. Configure Providers

#### Via CLI:
```bash
python -m plexichat.ai.cli.ai_cli configure openai YOUR_API_KEY
python -m plexichat.ai.cli.ai_cli configure anthropic YOUR_API_KEY
```

#### Via Web UI:
Navigate to `/ui/ai/providers` and configure your providers.

#### Via API:
```bash
curl -X POST "http://localhost:8000/api/v1/ai/providers/configure" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "openai",
    "api_key": "your-api-key",
    "enabled": true
  }'
```

### 3. Test the System

#### Via CLI:
```bash
python -m plexichat.ai.cli.ai_cli test gpt-3.5-turbo "Hello, how are you?"
```

#### Via Web UI:
Navigate to `/ui/ai/test` for the interactive test interface.

#### Via API:
```bash
curl -X POST "http://localhost:8000/api/v1/ai/chat" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "test_user",
    "model_id": "gpt-3.5-turbo",
    "prompt": "Hello, how are you?",
    "max_tokens": 100
  }'
```

## API Endpoints

### Chat Completion
- `POST /api/v1/ai/chat` - Process AI chat completion

### Model Management
- `GET /api/v1/ai/models` - List available models
- `POST /api/v1/ai/models` - Add new model
- `DELETE /api/v1/ai/models/{model_id}` - Remove model
- `PATCH /api/v1/ai/models/{model_id}/status` - Update model status

### Provider Management
- `GET /api/v1/ai/providers` - List providers
- `POST /api/v1/ai/providers/configure` - Configure provider

### Permissions
- `POST /api/v1/ai/permissions` - Add user permission
- `GET /api/v1/ai/permissions/{user_id}` - Get user permissions

### Monitoring
- `GET /api/v1/ai/health` - System health check
- `GET /api/v1/ai/usage/{user_id}` - User usage statistics
- `GET /api/v1/ai/stats` - System statistics
- `POST /api/v1/ai/cache/clear` - Clear cache

## Web Interface

### Dashboard (`/ui/ai/`)
- System overview and health status
- Quick access to all management functions
- Recent activity monitoring

### Model Management (`/ui/ai/models`)
- Add, remove, and configure AI models
- View model health and performance
- Update model status and priorities

### Provider Configuration (`/ui/ai/providers`)
- Configure API keys and endpoints
- Enable/disable providers
- Test provider connectivity

### User Permissions (`/ui/ai/permissions`)
- Manage user access to models
- Set capability-based permissions
- Admin user management

### Monitoring (`/ui/ai/monitoring`)
- Real-time system health
- Usage analytics and cost tracking
- Performance metrics

### Test Interface (`/ui/ai/test`)
- Interactive AI model testing
- Compare model responses
- Debug and troubleshoot

## CLI Commands

### List Models
```bash
python -m plexichat.ai.cli.ai_cli list-models
python -m plexichat.ai.cli.ai_cli list-models --provider openai
python -m plexichat.ai.cli.ai_cli list-models --status available
```

### List Providers
```bash
python -m plexichat.ai.cli.ai_cli list-providers
```

### Health Check
```bash
python -m plexichat.ai.cli.ai_cli health
```

### Test Model
```bash
python -m plexichat.ai.cli.ai_cli test gpt-4 "Write a Python function to calculate fibonacci"
```

### Configure Provider
```bash
python -m plexichat.ai.cli.ai_cli configure openai sk-your-api-key
python -m plexichat.ai.cli.ai_cli configure anthropic your-api-key --base-url https://api.anthropic.com
```

### Add Model
```bash
# Create model config file
echo '{
  "id": "custom-model",
  "name": "Custom Model",
  "provider": "custom",
  "capabilities": ["text_generation", "chat_completion"],
  "max_tokens": 2048,
  "cost_per_1k_tokens": 0.001,
  "context_window": 4096
}' > custom_model.json

python -m plexichat.ai.cli.ai_cli add-model custom_model.json
```

### Remove Model
```bash
python -m plexichat.ai.cli.ai_cli remove-model custom-model
```

### Usage Statistics
```bash
python -m plexichat.ai.cli.ai_cli usage
python -m plexichat.ai.cli.ai_cli usage --user-id specific_user
```

### Clear Cache
```bash
python -m plexichat.ai.cli.ai_cli clear-cache
```

## Configuration

The AI system uses a JSON configuration file (`config/ai_config.json`) with the following structure:

- **models**: Array of AI model configurations
- **providers**: Provider-specific settings and API keys
- **access_control**: User permissions and admin settings

### Model Configuration
```json
{
  "id": "model-id",
  "name": "Model Name",
  "provider": "openai",
  "capabilities": ["text_generation", "chat_completion"],
  "max_tokens": 4096,
  "cost_per_1k_tokens": 0.002,
  "context_window": 4096,
  "supports_streaming": true,
  "supports_functions": false,
  "priority": 1,
  "fallback_models": ["backup-model-id"]
}
```

### Provider Configuration
```json
{
  "openai": {
    "api_key_encrypted": "encrypted-key",
    "base_url": "https://api.openai.com/v1",
    "enabled": true,
    "timeout": 30,
    "max_retries": 3
  }
}
```

## Security Features

- **Encrypted API Keys**: All API keys are encrypted at rest
- **Access Control**: Granular permissions per user and model
- **Rate Limiting**: Configurable rate limits per user and model
- **Admin Controls**: Separate admin user management
- **Audit Logging**: Complete request/response history

## Performance Optimization

- **Caching**: Intelligent request caching
- **Fallbacks**: Automatic failover to backup models
- **Health Monitoring**: Continuous model health checks
- **Load Balancing**: Smart model selection based on performance
- **Concurrent Processing**: Async request handling

## Troubleshooting

### Common Issues

1. **Provider Not Available**: Check API key configuration and network connectivity
2. **Model Not Found**: Verify model ID and provider configuration
3. **Permission Denied**: Check user permissions for the specific model
4. **Rate Limited**: Adjust rate limits or wait for reset
5. **High Latency**: Check model health and consider fallbacks

### Debug Commands
```bash
# Check system health
python -m plexichat.ai.cli.ai_cli health

# Test specific model
python -m plexichat.ai.cli.ai_cli test model-id "test prompt"

# View usage stats
python -m plexichat.ai.cli.ai_cli usage

# Clear cache if needed
python -m plexichat.ai.cli.ai_cli clear-cache
```

## Integration

The AI abstraction layer integrates seamlessly with PlexiChat's main application:

- **FastAPI Integration**: Automatic router registration
- **WebUI Integration**: Admin panel integration
- **Authentication**: Uses PlexiChat's auth system
- **Logging**: Integrated with PlexiChat's logging system
- **Configuration**: Follows PlexiChat's config patterns

## Future Enhancements

- **Model Fine-tuning**: Support for custom model training
- **Advanced Analytics**: ML-powered usage insights
- **Auto-scaling**: Dynamic model scaling based on demand
- **Multi-region**: Geographic model distribution
- **Plugin System**: Extensible provider plugins
