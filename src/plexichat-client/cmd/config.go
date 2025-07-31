package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management",
	Long:  "Manage PlexiChat client configuration",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  "Display the current configuration settings",
	RunE:  runConfigShow,
}

var configSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set configuration value",
	Long:  "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	RunE:  runConfigSet,
}

var configGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get configuration value",
	Long:  "Get a configuration value",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigGet,
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration",
	Long:  "Create a new configuration file with default values",
	RunE:  runConfigInit,
}

var configEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit configuration file",
	Long:  "Open configuration file in default editor",
	RunE:  runConfigEdit,
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration",
	Long:  "Validate the current configuration file",
	RunE:  runConfigValidate,
}

var configBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup configuration",
	Long:  "Create a backup of the current configuration",
	RunE:  runConfigBackup,
}

var configRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore configuration",
	Long:  "Restore configuration from backup",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigRestore,
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configEditCmd)
	configCmd.AddCommand(configValidateCmd)
	configCmd.AddCommand(configBackupCmd)
	configCmd.AddCommand(configRestoreCmd)

	// Flags
	configShowCmd.Flags().Bool("secrets", false, "Show sensitive values (tokens, passwords)")
	configInitCmd.Flags().Bool("force", false, "Overwrite existing configuration file")
	configBackupCmd.Flags().StringP("output", "o", "", "Backup file path")
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	showSecrets, _ := cmd.Flags().GetBool("secrets")

	color.Cyan("Current Configuration:")
	fmt.Println("=====================")

	// Get all settings
	settings := viper.AllSettings()
	
	for key, value := range settings {
		// Hide sensitive values unless --secrets flag is used
		if !showSecrets && isSensitiveKey(key) {
			fmt.Printf("%s: %s\n", key, color.YellowString("[HIDDEN]"))
		} else {
			fmt.Printf("%s: %v\n", key, value)
		}
	}

	configFile := viper.ConfigFileUsed()
	if configFile != "" {
		fmt.Printf("\nConfig file: %s\n", configFile)
	} else {
		color.Yellow("No config file found")
	}

	return nil
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	key := args[0]
	value := args[1]

	// Convert string values to appropriate types
	var finalValue interface{} = value
	
	// Try to parse as boolean
	if strings.ToLower(value) == "true" {
		finalValue = true
	} else if strings.ToLower(value) == "false" {
		finalValue = false
	}

	viper.Set(key, finalValue)

	// Save to config file
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configFile = filepath.Join(home, ".plexichat-client.yaml")
	}

	err := viper.WriteConfigAs(configFile)
	if err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	color.Green("✓ Configuration updated: %s = %v", key, finalValue)
	fmt.Printf("Saved to: %s\n", configFile)

	return nil
}

func runConfigGet(cmd *cobra.Command, args []string) error {
	key := args[0]
	value := viper.Get(key)

	if value == nil {
		color.Red("Configuration key '%s' not found", key)
		return nil
	}

	if isSensitiveKey(key) {
		color.Yellow("Warning: This is a sensitive configuration value")
	}

	fmt.Printf("%s: %v\n", key, value)
	return nil
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	force, _ := cmd.Flags().GetBool("force")

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	configFile := filepath.Join(home, ".plexichat-client.yaml")

	// Check if file exists
	if _, err := os.Stat(configFile); err == nil && !force {
		return fmt.Errorf("configuration file already exists: %s (use --force to overwrite)", configFile)
	}

	// Create default configuration
	defaultConfig := map[string]interface{}{
		"url":                "http://localhost:8000",
		"timeout":            "30s",
		"retries":            3,
		"concurrent_requests": 10,
		"verbose":            false,
		"color":              true,
		"format":             "table",
		"chat": map[string]interface{}{
			"default_room":           1,
			"message_history_limit":  50,
			"auto_reconnect":         true,
			"ping_interval":          "30s",
		},
		"security": map[string]interface{}{
			"test_timeout":         "60s",
			"scan_timeout":         "300s",
			"max_concurrent_tests": 5,
			"report_format":        "json",
		},
		"benchmark": map[string]interface{}{
			"default_duration":      "30s",
			"default_concurrent":    10,
			"response_time_target":  "1ms",
			"microsecond_samples":   1000,
		},
		"logging": map[string]interface{}{
			"level":  "info",
			"format": "text",
		},
		"features": map[string]interface{}{
			"experimental_commands":   false,
			"beta_features":          false,
			"advanced_security":      true,
			"performance_monitoring": true,
		},
	}

	// Convert to YAML and write
	yamlData, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	err = os.WriteFile(configFile, yamlData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	color.Green("✓ Configuration file created: %s", configFile)
	fmt.Println("You can now edit this file or use 'plexichat-client config set' to modify values.")

	return nil
}

func runConfigEdit(cmd *cobra.Command, args []string) error {
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		return fmt.Errorf("no configuration file found. Use 'config init' to create one")
	}

	// Try to find an editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		// Default editors by platform
		editor = "notepad" // Windows default
	}

	fmt.Printf("Opening %s with %s...\n", configFile, editor)
	
	// Note: In a real implementation, you would use os/exec to launch the editor
	// For this example, we'll just show the path
	color.Yellow("Please manually edit the file: %s", configFile)
	
	return nil
}

func runConfigValidate(cmd *cobra.Command, args []string) error {
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		return fmt.Errorf("no configuration file found")
	}

	// Read and parse the config file
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config map[string]interface{}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("invalid YAML syntax: %w", err)
	}

	// Validate required fields and types
	validationErrors := []string{}

	// Check URL format
	if url, ok := config["url"].(string); ok {
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			validationErrors = append(validationErrors, "url must start with http:// or https://")
		}
	}

	// Check timeout format
	if timeout, ok := config["timeout"].(string); ok {
		if !strings.HasSuffix(timeout, "s") && !strings.HasSuffix(timeout, "m") && !strings.HasSuffix(timeout, "h") {
			validationErrors = append(validationErrors, "timeout must be a valid duration (e.g., 30s, 5m, 1h)")
		}
	}

	if len(validationErrors) > 0 {
		color.Red("Configuration validation failed:")
		for _, err := range validationErrors {
			fmt.Printf("  - %s\n", err)
		}
		return fmt.Errorf("configuration validation failed")
	}

	color.Green("✓ Configuration is valid")
	return nil
}

func runConfigBackup(cmd *cobra.Command, args []string) error {
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		return fmt.Errorf("no configuration file found")
	}

	outputPath, _ := cmd.Flags().GetString("output")
	if outputPath == "" {
		outputPath = configFile + ".backup"
	}

	// Copy config file
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	err = os.WriteFile(outputPath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	color.Green("✓ Configuration backed up to: %s", outputPath)
	return nil
}

func runConfigRestore(cmd *cobra.Command, args []string) error {
	backupPath := args[0]

	// Check if backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", backupPath)
	}

	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configFile = filepath.Join(home, ".plexichat-client.yaml")
	}

	// Copy backup to config file
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	err = os.WriteFile(configFile, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to restore configuration: %w", err)
	}

	color.Green("✓ Configuration restored from: %s", backupPath)
	fmt.Printf("Restored to: %s\n", configFile)

	return nil
}

func isSensitiveKey(key string) bool {
	sensitiveKeys := []string{
		"token", "refresh_token", "api_key", "password",
		"proxy.password", "tls.client_key",
	}

	key = strings.ToLower(key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(key, sensitive) {
			return true
		}
	}
	return false
}
