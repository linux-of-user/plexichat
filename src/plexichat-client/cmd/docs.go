package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var docsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Documentation generation",
	Long:  "Generate documentation for PlexiChat client",
}

var docsGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate documentation",
	Long:  "Generate documentation in various formats",
	RunE:  runDocsGenerate,
}

var docsServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve documentation",
	Long:  "Start a local server to view documentation",
	RunE:  runDocsServe,
}

var docsExamplesCmd = &cobra.Command{
	Use:   "examples",
	Short: "Generate usage examples",
	Long:  "Generate comprehensive usage examples",
	RunE:  runDocsExamples,
}

func init() {
	rootCmd.AddCommand(docsCmd)
	docsCmd.AddCommand(docsGenerateCmd)
	docsCmd.AddCommand(docsServeCmd)
	docsCmd.AddCommand(docsExamplesCmd)

	// Documentation flags
	docsGenerateCmd.Flags().StringP("format", "f", "markdown", "Documentation format (markdown, html, man)")
	docsGenerateCmd.Flags().StringP("output", "o", "docs", "Output directory")
	docsGenerateCmd.Flags().Bool("include-examples", true, "Include usage examples")
	docsGenerateCmd.Flags().Bool("include-api", true, "Include API documentation")

	docsServeCmd.Flags().IntP("port", "p", 8080, "Server port")
	docsServeCmd.Flags().String("host", "localhost", "Server host")

	docsExamplesCmd.Flags().StringP("output", "o", "examples", "Output directory")
	docsExamplesCmd.Flags().String("format", "markdown", "Examples format")
}

func runDocsGenerate(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	outputDir, _ := cmd.Flags().GetString("output")
	includeExamples, _ := cmd.Flags().GetBool("include-examples")
	includeAPI, _ := cmd.Flags().GetBool("include-api")

	color.Cyan("📚 Generating Documentation")
	fmt.Printf("Format: %s\n", format)
	fmt.Printf("Output: %s\n", outputDir)
	fmt.Println()

	// Create output directory
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	switch format {
	case "markdown":
		err = generateMarkdownDocs(outputDir, includeExamples, includeAPI)
	case "html":
		err = generateHTMLDocs(outputDir, includeExamples, includeAPI)
	case "man":
		err = generateManPages(outputDir)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to generate documentation: %w", err)
	}

	color.Green("✓ Documentation generated successfully!")
	fmt.Printf("Output directory: %s\n", outputDir)

	return nil
}

func runDocsServe(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")
	host, _ := cmd.Flags().GetString("host")

	color.Cyan("🌐 Starting Documentation Server")
	fmt.Printf("Server: http://%s:%d\n", host, port)
	fmt.Println("Press Ctrl+C to stop")

	// In a real implementation, this would start an HTTP server
	// For now, we'll just simulate it
	color.Yellow("Documentation server functionality not yet implemented")
	color.Yellow("Use a static file server to serve the generated docs")

	return nil
}

func runDocsExamples(cmd *cobra.Command, args []string) error {
	outputDir, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")

	color.Cyan("📖 Generating Usage Examples")
	fmt.Printf("Output: %s\n", outputDir)
	fmt.Printf("Format: %s\n", format)
	fmt.Println()

	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	err = generateExamples(outputDir, format)
	if err != nil {
		return fmt.Errorf("failed to generate examples: %w", err)
	}

	color.Green("✓ Examples generated successfully!")
	return nil
}

func generateMarkdownDocs(outputDir string, includeExamples, includeAPI bool) error {
	// Generate command documentation
	err := doc.GenMarkdownTree(rootCmd, outputDir)
	if err != nil {
		return err
	}

	// Generate main README
	readme := generateMainReadme()
	err = os.WriteFile(filepath.Join(outputDir, "README.md"), []byte(readme), 0644)
	if err != nil {
		return err
	}

	// Generate quick start guide
	quickStart := generateQuickStartGuide()
	err = os.WriteFile(filepath.Join(outputDir, "QUICKSTART.md"), []byte(quickStart), 0644)
	if err != nil {
		return err
	}

	// Generate configuration guide
	configGuide := generateConfigurationGuide()
	err = os.WriteFile(filepath.Join(outputDir, "CONFIGURATION.md"), []byte(configGuide), 0644)
	if err != nil {
		return err
	}

	if includeExamples {
		err = generateExamples(filepath.Join(outputDir, "examples"), "markdown")
		if err != nil {
			return err
		}
	}

	if includeAPI {
		apiDocs := generateAPIDocs()
		err = os.WriteFile(filepath.Join(outputDir, "API.md"), []byte(apiDocs), 0644)
		if err != nil {
			return err
		}
	}

	return nil
}

func generateHTMLDocs(outputDir string, includeExamples, includeAPI bool) error {
	// For HTML generation, we would typically use a template engine
	// For now, we'll generate basic HTML

	htmlTemplate := `<!DOCTYPE html>
<html>
<head>
	<title>PlexiChat Go Client Documentation</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; }
		h1, h2, h3 { color: #333; }
		code { background: #f4f4f4; padding: 2px 4px; }
		pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
	</style>
</head>
<body>
	<h1>PlexiChat Go Client Documentation</h1>
	<p>Generated on: %s</p>
	<p>This is a placeholder for HTML documentation.</p>
	<p>In a full implementation, this would contain:</p>
	<ul>
		<li>Complete command reference</li>
		<li>API documentation</li>
		<li>Usage examples</li>
		<li>Configuration guide</li>
	</ul>
</body>
</html>`

	html := fmt.Sprintf(htmlTemplate, time.Now().Format("2006-01-02 15:04:05"))
	return os.WriteFile(filepath.Join(outputDir, "index.html"), []byte(html), 0644)
}

func generateManPages(outputDir string) error {
	return doc.GenManTree(rootCmd, &doc.GenManHeader{
		Title:   "PlexiChat Client",
		Section: "1",
		Source:  "PlexiChat Go Client",
		Manual:  "PlexiChat Manual",
	}, outputDir)
}

func generateExamples(outputDir, format string) error {
	examples := map[string]string{
		"basic-usage":         generateBasicUsageExample(),
		"authentication":      generateAuthExample(),
		"chat-operations":     generateChatExample(),
		"file-management":     generateFileExample(),
		"admin-tasks":         generateAdminExample(),
		"security-testing":    generateSecurityExample(),
		"performance-testing": generatePerformanceExample(),
		"automation":          generateAutomationExample(),
		"monitoring":          generateMonitoringExample(),
		"configuration":       generateConfigExample(),
	}

	for name, content := range examples {
		filename := fmt.Sprintf("%s.%s", name, getFileExtension(format))
		err := os.WriteFile(filepath.Join(outputDir, filename), []byte(content), 0644)
		if err != nil {
			return err
		}
	}

	return nil
}

func generateMainReadme() string {
	return `# PlexiChat Go Client Documentation

Welcome to the comprehensive documentation for the PlexiChat Go Client.

## Overview

The PlexiChat Go Client is a feature-rich command-line interface for interacting with PlexiChat servers. It provides access to all PlexiChat features including real-time messaging, file management, administration, security testing, and performance monitoring.

## Quick Links

- [Quick Start Guide](QUICKSTART.md)
- [Configuration Guide](CONFIGURATION.md)
- [API Documentation](API.md)
- [Examples](examples/)

## Features

### Core Features
- **Authentication & User Management**
- **Real-time Chat Messaging**
- **File Upload & Download**
- **Administrative Operations**
- **Security Testing & Vulnerability Scanning**
- **Performance Testing & Benchmarking**
- **Monitoring & Analytics**
- **Automation & Scripting**

### Advanced Features
- **Interactive Mode**
- **Plugin System**
- **Configuration Management**
- **Comprehensive Testing Framework**
- **Documentation Generation**

## Installation

` + "```bash" + `
# Build from source
git clone <repository>
cd plexichat-client
go build -o plexichat-client
` + "```" + `

## Basic Usage

` + "```bash" + `
# Check server health
./plexichat-client health

# Login
./plexichat-client auth login

# Send a message
./plexichat-client chat send --message "Hello, World!" --room 1

# Start interactive mode
./plexichat-client interactive
` + "```" + `

## Documentation Structure

- **Command Reference**: Auto-generated command documentation
- **Quick Start**: Get up and running quickly
- **Configuration**: Detailed configuration options
- **Examples**: Comprehensive usage examples
- **API Reference**: Complete API documentation

Generated on: ` + time.Now().Format("2006-01-02 15:04:05") + `
`
}

func generateQuickStartGuide() string {
	return `# Quick Start Guide

Get up and running with PlexiChat Go Client in minutes.

## 1. Installation

` + "```bash" + `
# Clone and build
git clone <repository>
cd plexichat-client
make build
` + "```" + `

## 2. Configuration

` + "```bash" + `
# Initialize configuration
./plexichat-client config init

# Set server URL
./plexichat-client config set url "https://your-plexichat-server.com"
` + "```" + `

## 3. Authentication

` + "```bash" + `
# Login
./plexichat-client auth login --username your-username

# Check current user
./plexichat-client auth whoami
` + "```" + `

## 4. Basic Operations

` + "```bash" + `
# List chat rooms
./plexichat-client chat rooms

# Send a message
./plexichat-client chat send --room 1 --message "Hello!"

# Upload a file
./plexichat-client files upload --file document.pdf

# Check server health
./plexichat-client health
` + "```" + `

## 5. Interactive Mode

` + "```bash" + `
# Start interactive shell
./plexichat-client interactive
` + "```" + `

## Next Steps

- Explore the [examples](examples/) directory
- Read the [configuration guide](CONFIGURATION.md)
- Check out [advanced features](API.md)
`
}

func generateConfigurationGuide() string {
	return `# Configuration Guide

Complete guide to configuring the PlexiChat Go Client.

## Configuration File

The client uses a YAML configuration file located at ` + "`~/.plexichat-client.yaml`" + `.

## Basic Configuration

` + "```yaml" + `
# Server settings
url: "http://localhost:8000"
timeout: "30s"
retries: 3

# Authentication
token: ""
refresh_token: ""
api_key: ""

# Output settings
verbose: false
color: true
format: "table"
` + "```" + `

## Advanced Configuration

` + "```yaml" + `
# Chat settings
chat:
  default_room: 1
  message_history_limit: 50
  auto_reconnect: true

# Security testing
security:
  test_timeout: "60s"
  max_concurrent_tests: 5

# Performance testing
benchmark:
  default_duration: "30s"
  default_concurrent: 10
` + "```" + `

## Environment Variables

- ` + "`PLEXICHAT_URL`" + ` - Server URL
- ` + "`PLEXICHAT_TOKEN`" + ` - Authentication token
- ` + "`PLEXICHAT_CONFIG`" + ` - Configuration file path

## Configuration Commands

` + "```bash" + `
# Show current configuration
./plexichat-client config show

# Set a value
./plexichat-client config set key value

# Get a value
./plexichat-client config get key

# Validate configuration
./plexichat-client config validate
` + "```" + `
`
}

func generateAPIDocs() string {
	return `# API Documentation

Complete API reference for the PlexiChat Go Client.

## Authentication

### Login
` + "```bash" + `
plexichat-client auth login [flags]
` + "```" + `

### Register
` + "```bash" + `
plexichat-client auth register [flags]
` + "```" + `

## Chat Operations

### Send Message
` + "```bash" + `
plexichat-client chat send --message "text" --room ID
` + "```" + `

### Listen to Chat
` + "```bash" + `
plexichat-client chat listen [--room ID | --all]
` + "```" + `

## File Operations

### Upload File
` + "```bash" + `
plexichat-client files upload --file path
` + "```" + `

### Download File
` + "```bash" + `
plexichat-client files download --id ID --output path
` + "```" + `

## Administrative Operations

### List Users
` + "```bash" + `
plexichat-client admin users list
` + "```" + `

### System Statistics
` + "```bash" + `
plexichat-client admin stats
` + "```" + `

## Security Testing

### Run Security Test
` + "```bash" + `
plexichat-client security test --endpoint /api/endpoint
` + "```" + `

### Vulnerability Scan
` + "```bash" + `
plexichat-client security scan --all
` + "```" + `

## Performance Testing

### Load Test
` + "```bash" + `
plexichat-client benchmark load --endpoint /api/endpoint
` + "```" + `

### Response Time Test
` + "```bash" + `
plexichat-client benchmark response --endpoint /api/endpoint
` + "```" + `
`
}

func generateBasicUsageExample() string {
	return `# Basic Usage Examples

## Health Check
` + "```bash" + `
# Check if server is running
plexichat-client health

# Get version information
plexichat-client version
` + "```" + `

## Authentication
` + "```bash" + `
# Login with username/password
plexichat-client auth login --username admin --password secret

# Login with prompts
plexichat-client auth login

# Check current user
plexichat-client auth whoami

# Logout
plexichat-client auth logout
` + "```" + `

## Basic Chat
` + "```bash" + `
# List available rooms
plexichat-client chat rooms

# Send a message
plexichat-client chat send --room 1 --message "Hello, World!"

# Get chat history
plexichat-client chat history --room 1 --limit 20
` + "```" + `
`
}

func generateAuthExample() string {
	return `# Authentication Examples

## User Registration
` + "```bash" + `
# Register new user account
plexichat-client auth register \
  --username newuser \
  --email user@example.com \
  --password secretpass \
  --type user

# Register bot account
plexichat-client auth register \
  --username chatbot \
  --email bot@example.com \
  --password botpass \
  --type bot
` + "```" + `

## Login Methods
` + "```bash" + `
# Interactive login
plexichat-client auth login

# Command line login
plexichat-client auth login --username admin --password secret

# Login and save credentials
plexichat-client auth login --username admin --save
` + "```" + `

## Token Management
` + "```bash" + `
# Check current authentication status
plexichat-client auth whoami

# Logout and clear tokens
plexichat-client auth logout
` + "```" + `
`
}

func generateChatExample() string {
	return `# Chat Examples

## Real-time Chat
` + "```bash" + `
# Listen to all rooms
plexichat-client chat listen --all

# Listen to specific room
plexichat-client chat listen --room 1

# Send messages while listening
plexichat-client chat send --room 1 --message "Hello!"
` + "```" + `

## Message Management
` + "```bash" + `
# Get recent messages
plexichat-client chat history --room 1 --limit 50

# Get messages from specific page
plexichat-client chat history --room 1 --page 2 --limit 25
` + "```" + `

## Room Operations
` + "```bash" + `
# List all rooms
plexichat-client chat rooms

# Get room information
plexichat-client chat rooms --detailed
` + "```" + `
`
}

func generateFileExample() string {
	return `# File Management Examples

## File Upload
` + "```bash" + `
# Upload a file
plexichat-client files upload --file document.pdf

# Upload with description
plexichat-client files upload --file image.jpg --description "Profile picture"

# Upload as public file
plexichat-client files upload --file data.csv --public
` + "```" + `

## File Download
` + "```bash" + `
# Download file by ID
plexichat-client files download --id 123 --output downloaded-file.pdf

# Download to current directory
plexichat-client files download --id 123
` + "```" + `

## File Management
` + "```bash" + `
# List all files
plexichat-client files list

# List with pagination
plexichat-client files list --limit 20 --page 2

# Filter by file type
plexichat-client files list --type "image/jpeg"

# Get file information
plexichat-client files info --id 123

# Delete file
plexichat-client files delete --id 123
` + "```" + `
`
}

func generateAdminExample() string {
	return `# Administrative Examples

## User Management
` + "```bash" + `
# List all users
plexichat-client admin users list

# List with filters
plexichat-client admin users list --type bot --limit 50

# Get system statistics
plexichat-client admin stats
` + "```" + `

## Configuration Management
` + "```bash" + `
# Configure rate limiting
plexichat-client admin config rate-limit \
  --requests-per-minute 100 \
  --burst-limit 200 \
  --enable

# Configure security settings
plexichat-client admin config security \
  --max-login-attempts 5 \
  --lockout-duration 15m \
  --require-https
` + "```" + `
`
}

func generateSecurityExample() string {
	return `# Security Testing Examples

## Vulnerability Testing
` + "```bash" + `
# Run full security scan
plexichat-client security test --full-scan

# Test specific endpoint
plexichat-client security test \
  --endpoint /api/v1/auth/login \
  --type sql_injection

# Test with custom payload
plexichat-client security test \
  --endpoint /api/v1/users \
  --payload "'; DROP TABLE users; --" \
  --type sql_injection
` + "```" + `

## Security Scanning
` + "```bash" + `
# Scan all endpoints
plexichat-client security scan --all

# Scan specific endpoints
plexichat-client security scan \
  --endpoints /api/v1/auth/login,/api/v1/users

# Filter by severity
plexichat-client security scan --severity critical
` + "```" + `

## Security Reporting
` + "```bash" + `
# Generate security report
plexichat-client security report \
  --format html \
  --output security-report.html \
  --detailed
` + "```" + `
`
}

func generatePerformanceExample() string {
	return `# Performance Testing Examples

## Load Testing
` + "```bash" + `
# Basic load test
plexichat-client benchmark load \
  --endpoint /api/v1/health \
  --concurrent 10 \
  --duration 60s

# Load test with rate limiting
plexichat-client benchmark load \
  --endpoint /api/v1/messages \
  --concurrent 20 \
  --duration 120s \
  --requests-per-sec 100
` + "```" + `

## Response Time Testing
` + "```bash" + `
# Test response times
plexichat-client benchmark response \
  --endpoint /api/v1/health \
  --samples 1000 \
  --target 1ms

# Microsecond performance test
plexichat-client benchmark microsecond \
  --endpoint /api/v1/health \
  --samples 10000 \
  --validate
` + "```" + `
`
}

func generateAutomationExample() string {
	return `# Automation Examples

## Script Creation
` + "```bash" + `
# Create basic script
plexichat-client script create basic-monitoring --template monitoring

# Create chat bot script
plexichat-client script create chat-bot --template chat-bot

# Create security script
plexichat-client script create security-scan --template security
` + "```" + `

## Script Execution
` + "```bash" + `
# Run script
plexichat-client script run scripts/monitoring.json

# Run with variables
plexichat-client script run scripts/chat-bot.json \
  --var room=1 \
  --var message="Bot is online"

# Dry run
plexichat-client script run scripts/security-scan.json --dry-run
` + "```" + `

## Workflow Automation
` + "```bash" + `
# Schedule automation
plexichat-client automate schedule \
  --cron "0 */6 * * *" \
  --script scripts/monitoring.json

# Run workflow
plexichat-client automate workflow workflows/daily-checks.json
` + "```" + `
`
}

func generateMonitoringExample() string {
	return `# Monitoring Examples

## System Monitoring
` + "```bash" + `
# Monitor system metrics
plexichat-client monitor system --interval 5s

# Monitor in JSON format
plexichat-client monitor system --interval 10s --json
` + "```" + `

## Chat Monitoring
` + "```bash" + `
# Monitor all chat activity
plexichat-client monitor chat

# Monitor specific room
plexichat-client monitor chat --room 1
` + "```" + `

## User Activity Monitoring
` + "```bash" + `
# Monitor all user activity
plexichat-client monitor users

# Monitor specific user
plexichat-client monitor users --user admin
` + "```" + `

## Alert Monitoring
` + "```bash" + `
# Monitor all alerts
plexichat-client monitor alerts

# Monitor critical alerts only
plexichat-client monitor alerts --level critical
` + "```" + `

## Analytics
` + "```bash" + `
# Generate analytics report
plexichat-client analytics --period 24h --format json

# Save analytics to file
plexichat-client analytics \
  --period 7d \
  --format html \
  --output weekly-report.html
` + "```" + `
`
}

func generateConfigExample() string {
	return `# Configuration Examples

## Basic Configuration
` + "```bash" + `
# Initialize configuration
plexichat-client config init

# Show current configuration
plexichat-client config show

# Show including sensitive values
plexichat-client config show --secrets
` + "```" + `

## Setting Values
` + "```bash" + `
# Set server URL
plexichat-client config set url "https://plexichat.example.com"

# Set timeout
plexichat-client config set timeout "60s"

# Set boolean values
plexichat-client config set verbose true
plexichat-client config set color false
` + "```" + `

## Configuration Management
` + "```bash" + `
# Validate configuration
plexichat-client config validate

# Backup configuration
plexichat-client config backup --output config-backup.yaml

# Restore configuration
plexichat-client config restore config-backup.yaml

# Edit configuration file
plexichat-client config edit
` + "```" + `
`
}

func getFileExtension(format string) string {
	switch format {
	case "markdown":
		return "md"
	case "html":
		return "html"
	case "text":
		return "txt"
	default:
		return "md"
	}
}
