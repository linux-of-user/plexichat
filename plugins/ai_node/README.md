# AI Node Plugin for PlexiChat

A dedicated AI processing node that provides local AI model hosting, HuggingFace integration, and distributed inference capabilities for PlexiChat.

## Features

### 🤖 AI Model Support
- **HuggingFace Integration**: Browse, download, and install models directly from HuggingFace Hub
- **Multiple Frameworks**: Support for Transformers, llama.cpp, bitnet.cpp, and ONNX
- **Local Model Hosting**: Run models locally without external API dependencies
- **GPU Acceleration**: Automatic GPU detection and utilization when available
- **Model Quantization**: Reduce memory usage with quantized models

### 🌐 Web Management Interface
- **Setup Wizard**: Easy first-time configuration
- **Model Browser**: Search and install models from HuggingFace
- **Real-time Monitoring**: Track model performance and usage
- **Resource Management**: Monitor memory and GPU usage

### 🔧 Advanced Features
- **Distributed Inference**: Integrate with PlexiChat's clustering system
- **Background Processing**: Queue inference requests for batch processing
- **Automatic Model Management**: Load/unload models based on usage patterns
- **Caching**: Intelligent caching of inference results
- **API Integration**: RESTful API for programmatic access

## Installation

### Prerequisites
- Python 3.8 or higher
- 8GB+ RAM (32GB recommended for larger models)
- CUDA-compatible GPU (optional but recommended)

### Quick Setup
```bash
# Navigate to the plugin directory
cd plugins/ai_node

# Run the setup script
python setup.py

# The setup script will:
# - Install required dependencies
# - Create necessary directories
# - Generate default configuration
# - Check for GPU support
```

### Manual Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Create directories
mkdir -p models cache logs

# Copy default configuration
cp config.example.json config.json
```

## Configuration

Edit `config.json` to customize the AI node:

```json
{
  "max_models": 10,
  "model_cache_size_gb": 50,
  "inference_timeout": 30,
  "enable_gpu": true,
  "enable_quantization": true,
  "web_ui_port": 8080,
  "default_models": [
    "microsoft/DialoGPT-medium",
    "sentence-transformers/all-MiniLM-L6-v2"
  ]
}
```

## Usage

### Web Interface
1. Start PlexiChat with the AI Node plugin enabled
2. Open your browser to `http://localhost:8080`
3. Use the web interface to:
   - Search for models on HuggingFace
   - Install and manage models
   - Monitor performance
   - Run test inferences

### CLI Commands
```bash
# Show AI node status
plexichat plugin ai-node status

# List available models
plexichat plugin ai-node list-models

# Load a model
plexichat plugin ai-node load-model microsoft/DialoGPT-medium

# Search HuggingFace models
plexichat plugin ai-node search-hf "conversational ai"

# Install a model from HuggingFace
plexichat plugin ai-node install-hf microsoft/DialoGPT-large

# Run inference
plexichat plugin ai-node inference microsoft/DialoGPT-medium "Hello, how are you?"
```

### API Endpoints
- `GET /` - Web dashboard
- `GET /api/models` - List models
- `POST /api/models/{model_id}/load` - Load model
- `POST /api/models/{model_id}/unload` - Unload model
- `POST /api/huggingface/search` - Search HuggingFace models
- `POST /api/huggingface/install` - Install HuggingFace model
- `POST /api/inference` - Run inference

## Supported Model Types

### Text Generation
- GPT models (GPT-2, GPT-3.5, GPT-4)
- LLaMA models
- Mistral models
- CodeLlama models

### Text Classification
- BERT models
- RoBERTa models
- DistilBERT models

### Embeddings
- Sentence Transformers
- E5 models
- BGE models

### Other Types
- Summarization models
- Translation models
- Question-answering models

## Integration with PlexiChat

### Clustering Integration
The AI node automatically registers with PlexiChat's clustering system, allowing:
- Load balancing across multiple AI nodes
- Automatic failover
- Distributed model hosting

### AI Services Integration
Integrates with PlexiChat's AI coordinator to provide:
- Content moderation
- Chatbot responses
- Semantic search
- Recommendations

### Security Integration
- Respects PlexiChat's permission system
- Secure model downloads
- Sandboxed inference execution

## Performance Optimization

### GPU Acceleration
- Automatic CUDA detection
- Mixed precision inference
- Batch processing optimization

### Memory Management
- Automatic model unloading
- Memory usage monitoring
- Configurable cache limits

### Caching
- Inference result caching
- Model weight caching
- Smart cache eviction

## Troubleshooting

### Common Issues

**GPU not detected**
```bash
# Check CUDA installation
nvidia-smi

# Install PyTorch with CUDA support
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

**Out of memory errors**
- Reduce `max_models` in configuration
- Enable quantization
- Use smaller models
- Increase system RAM

**Model download failures**
- Check internet connection
- Verify HuggingFace Hub access
- Check disk space

### Logs
Check logs in the `logs/` directory:
- `ai_node.log` - General plugin logs
- `inference.log` - Inference-specific logs
- `web_ui.log` - Web interface logs

## Development

### Adding New Frameworks
1. Implement framework-specific loading in `_load_*_model` methods
2. Add inference logic in `_run_*_inference` methods
3. Update framework detection in `_initialize_frameworks`

### Custom Model Types
1. Add new type to `ModelType` enum
2. Implement type detection in `_detect_model_type`
3. Add inference logic for the new type

## License

This plugin is part of PlexiChat and follows the same license terms.

## Support

For support and questions:
- Check the PlexiChat documentation
- Open an issue on the PlexiChat repository
- Join the PlexiChat community forums
