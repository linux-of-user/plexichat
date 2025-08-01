package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var pluginsCmd = &cobra.Command{
	Use:   "plugins",
	Short: "Plugin management",
	Long:  "Manage PlexiChat client plugins and extensions",
}

var pluginsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available plugins",
	Long:  "List all available plugins and their status",
	RunE:  runPluginsList,
}

var pluginsInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install a plugin",
	Long:  "Install a plugin from repository or local file",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginsInstall,
}

var pluginsUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall a plugin",
	Long:  "Uninstall an installed plugin",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginsUninstall,
}

var pluginsEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable a plugin",
	Long:  "Enable a disabled plugin",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginsEnable,
}

var pluginsDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable a plugin",
	Long:  "Disable an enabled plugin",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginsDisable,
}

var pluginsInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show plugin information",
	Long:  "Show detailed information about a plugin",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginsInfo,
}

var pluginsSearchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search for plugins",
	Long:  "Search for plugins in the repository",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginsSearch,
}

var pluginsUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update plugins",
	Long:  "Update all installed plugins or a specific plugin",
	RunE:  runPluginsUpdate,
}

type Plugin struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Author      string            `json:"author"`
	Homepage    string            `json:"homepage"`
	Repository  string            `json:"repository"`
	License     string            `json:"license"`
	Tags        []string          `json:"tags"`
	Commands    []PluginCommand   `json:"commands"`
	Config      map[string]string `json:"config"`
	Enabled     bool              `json:"enabled"`
	Installed   bool              `json:"installed"`
}

type PluginCommand struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Usage       string `json:"usage"`
}

func init() {
	rootCmd.AddCommand(pluginsCmd)
	pluginsCmd.AddCommand(pluginsListCmd)
	pluginsCmd.AddCommand(pluginsInstallCmd)
	pluginsCmd.AddCommand(pluginsUninstallCmd)
	pluginsCmd.AddCommand(pluginsEnableCmd)
	pluginsCmd.AddCommand(pluginsDisableCmd)
	pluginsCmd.AddCommand(pluginsInfoCmd)
	pluginsCmd.AddCommand(pluginsSearchCmd)
	pluginsCmd.AddCommand(pluginsUpdateCmd)

	// Flags
	pluginsListCmd.Flags().Bool("enabled", false, "Show only enabled plugins")
	pluginsListCmd.Flags().Bool("disabled", false, "Show only disabled plugins")
	pluginsListCmd.Flags().Bool("installed", false, "Show only installed plugins")
	pluginsInstallCmd.Flags().Bool("force", false, "Force installation even if plugin exists")
	pluginsUpdateCmd.Flags().String("plugin", "", "Update specific plugin")
}

func runPluginsList(cmd *cobra.Command, args []string) error {
	enabledOnly, _ := cmd.Flags().GetBool("enabled")
	disabledOnly, _ := cmd.Flags().GetBool("disabled")
	installedOnly, _ := cmd.Flags().GetBool("installed")

	plugins, err := getAvailablePlugins()
	if err != nil {
		return fmt.Errorf("failed to get plugins: %w", err)
	}

	// Filter plugins based on flags
	var filteredPlugins []Plugin
	for _, plugin := range plugins {
		if enabledOnly && !plugin.Enabled {
			continue
		}
		if disabledOnly && plugin.Enabled {
			continue
		}
		if installedOnly && !plugin.Installed {
			continue
		}
		filteredPlugins = append(filteredPlugins, plugin)
	}

	if len(filteredPlugins) == 0 {
		fmt.Println("No plugins found matching criteria.")
		return nil
	}

	// Display plugins in table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "Version", "Status", "Description"})
	table.SetBorder(false)
	table.SetRowSeparator("-")
	table.SetColumnSeparator("|")
	table.SetCenterSeparator("+")

	for _, plugin := range filteredPlugins {
		status := "Not Installed"
		if plugin.Installed {
			if plugin.Enabled {
				status = color.GreenString("Enabled")
			} else {
				status = color.YellowString("Disabled")
			}
		}

		description := plugin.Description
		if len(description) > 50 {
			description = description[:47] + "..."
		}

		table.Append([]string{
			plugin.Name,
			plugin.Version,
			status,
			description,
		})
	}

	fmt.Println("Available Plugins:")
	table.Render()
	fmt.Printf("Total: %d plugins\n", len(filteredPlugins))

	return nil
}

func runPluginsInstall(cmd *cobra.Command, args []string) error {
	pluginName := args[0]
	force, _ := cmd.Flags().GetBool("force")

	// Check if plugin is already installed
	if !force {
		plugins, err := getInstalledPlugins()
		if err != nil {
			return fmt.Errorf("failed to check installed plugins: %w", err)
		}

		for _, plugin := range plugins {
			if plugin.Name == pluginName {
				return fmt.Errorf("plugin '%s' is already installed (use --force to reinstall)", pluginName)
			}
		}
	}

	fmt.Printf("Installing plugin: %s\n", pluginName)

	// Simulate plugin installation
	err := installPlugin(pluginName)
	if err != nil {
		return fmt.Errorf("failed to install plugin: %w", err)
	}

	color.Green("✓ Plugin '%s' installed successfully!", pluginName)
	fmt.Println("Use 'plexichat-client plugins enable' to enable the plugin.")

	return nil
}

func runPluginsUninstall(cmd *cobra.Command, args []string) error {
	pluginName := args[0]

	fmt.Printf("Uninstalling plugin: %s\n", pluginName)

	err := uninstallPlugin(pluginName)
	if err != nil {
		return fmt.Errorf("failed to uninstall plugin: %w", err)
	}

	color.Green("✓ Plugin '%s' uninstalled successfully!", pluginName)
	return nil
}

func runPluginsEnable(cmd *cobra.Command, args []string) error {
	pluginName := args[0]

	err := enablePlugin(pluginName)
	if err != nil {
		return fmt.Errorf("failed to enable plugin: %w", err)
	}

	color.Green("✓ Plugin '%s' enabled!", pluginName)
	return nil
}

func runPluginsDisable(cmd *cobra.Command, args []string) error {
	pluginName := args[0]

	err := disablePlugin(pluginName)
	if err != nil {
		return fmt.Errorf("failed to disable plugin: %w", err)
	}

	color.Yellow("Plugin '%s' disabled", pluginName)
	return nil
}

func runPluginsInfo(cmd *cobra.Command, args []string) error {
	pluginName := args[0]

	plugin, err := getPluginInfo(pluginName)
	if err != nil {
		return fmt.Errorf("failed to get plugin info: %w", err)
	}

	color.Cyan("Plugin Information:")
	fmt.Printf("Name: %s\n", plugin.Name)
	fmt.Printf("Version: %s\n", plugin.Version)
	fmt.Printf("Description: %s\n", plugin.Description)
	fmt.Printf("Author: %s\n", plugin.Author)
	fmt.Printf("License: %s\n", plugin.License)
	fmt.Printf("Homepage: %s\n", plugin.Homepage)
	fmt.Printf("Repository: %s\n", plugin.Repository)

	if len(plugin.Tags) > 0 {
		fmt.Printf("Tags: %s\n", strings.Join(plugin.Tags, ", "))
	}

	if plugin.Installed {
		if plugin.Enabled {
			color.Green("Status: Enabled")
		} else {
			color.Yellow("Status: Disabled")
		}
	} else {
		color.Red("Status: Not Installed")
	}

	if len(plugin.Commands) > 0 {
		fmt.Println("\nCommands:")
		for _, cmd := range plugin.Commands {
			fmt.Printf("  %s - %s\n", cmd.Name, cmd.Description)
			if cmd.Usage != "" {
				fmt.Printf("    Usage: %s\n", cmd.Usage)
			}
		}
	}

	return nil
}

func runPluginsSearch(cmd *cobra.Command, args []string) error {
	query := args[0]

	fmt.Printf("Searching for plugins matching: %s\n", query)

	plugins, err := searchPlugins(query)
	if err != nil {
		return fmt.Errorf("failed to search plugins: %w", err)
	}

	if len(plugins) == 0 {
		fmt.Println("No plugins found matching the search criteria.")
		return nil
	}

	// Display search results
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "Version", "Description", "Tags"})
	table.SetBorder(false)

	for _, plugin := range plugins {
		description := plugin.Description
		if len(description) > 40 {
			description = description[:37] + "..."
		}

		tags := strings.Join(plugin.Tags, ", ")
		if len(tags) > 30 {
			tags = tags[:27] + "..."
		}

		table.Append([]string{
			plugin.Name,
			plugin.Version,
			description,
			tags,
		})
	}

	fmt.Printf("\nSearch Results (%d found):\n", len(plugins))
	table.Render()

	return nil
}

func runPluginsUpdate(cmd *cobra.Command, args []string) error {
	specificPlugin, _ := cmd.Flags().GetString("plugin")

	if specificPlugin != "" {
		fmt.Printf("Updating plugin: %s\n", specificPlugin)
		err := updatePlugin(specificPlugin)
		if err != nil {
			return fmt.Errorf("failed to update plugin: %w", err)
		}
		color.Green("✓ Plugin '%s' updated successfully!", specificPlugin)
	} else {
		fmt.Println("Updating all installed plugins...")

		plugins, err := getInstalledPlugins()
		if err != nil {
			return fmt.Errorf("failed to get installed plugins: %w", err)
		}

		updated := 0
		for _, plugin := range plugins {
			fmt.Printf("Checking %s...", plugin.Name)
			err := updatePlugin(plugin.Name)
			if err != nil {
				color.Red(" failed: %v", err)
			} else {
				color.Green(" updated")
				updated++
			}
		}

		color.Green("✓ Updated %d plugins", updated)
	}

	return nil
}

// Helper functions (these would be implemented with actual plugin management logic)

func getAvailablePlugins() ([]Plugin, error) {
	// This would typically fetch from a plugin repository
	// For demo purposes, return some example plugins
	return []Plugin{
		{
			Name:        "security-scanner",
			Version:     "1.2.0",
			Description: "Advanced security scanning and vulnerability assessment",
			Author:      "Security Team",
			License:     "MIT",
			Tags:        []string{"security", "scanning", "vulnerability"},
			Installed:   true,
			Enabled:     true,
			Commands: []PluginCommand{
				{Name: "scan", Description: "Run security scan", Usage: "scan [options]"},
				{Name: "report", Description: "Generate security report", Usage: "report [format]"},
			},
		},
		{
			Name:        "performance-monitor",
			Version:     "2.1.0",
			Description: "Real-time performance monitoring and alerting",
			Author:      "Performance Team",
			License:     "Apache-2.0",
			Tags:        []string{"performance", "monitoring", "alerts"},
			Installed:   false,
			Enabled:     false,
			Commands: []PluginCommand{
				{Name: "monitor", Description: "Start monitoring", Usage: "monitor [duration]"},
				{Name: "alerts", Description: "Configure alerts", Usage: "alerts [config]"},
			},
		},
		{
			Name:        "chat-bot",
			Version:     "1.0.5",
			Description: "Automated chat bot with AI responses",
			Author:      "AI Team",
			License:     "GPL-3.0",
			Tags:        []string{"chat", "bot", "ai", "automation"},
			Installed:   true,
			Enabled:     false,
			Commands: []PluginCommand{
				{Name: "bot-start", Description: "Start chat bot", Usage: "bot-start [room]"},
				{Name: "bot-config", Description: "Configure bot", Usage: "bot-config [options]"},
			},
		},
	}, nil
}

func getInstalledPlugins() ([]Plugin, error) {
	plugins, err := getAvailablePlugins()
	if err != nil {
		return nil, err
	}

	var installed []Plugin
	for _, plugin := range plugins {
		if plugin.Installed {
			installed = append(installed, plugin)
		}
	}

	return installed, nil
}

func getPluginInfo(name string) (*Plugin, error) {
	plugins, err := getAvailablePlugins()
	if err != nil {
		return nil, err
	}

	for _, plugin := range plugins {
		if plugin.Name == name {
			return &plugin, nil
		}
	}

	return nil, fmt.Errorf("plugin '%s' not found", name)
}

func searchPlugins(query string) ([]Plugin, error) {
	plugins, err := getAvailablePlugins()
	if err != nil {
		return nil, err
	}

	var results []Plugin
	query = strings.ToLower(query)

	for _, plugin := range plugins {
		// Search in name, description, and tags
		if strings.Contains(strings.ToLower(plugin.Name), query) ||
			strings.Contains(strings.ToLower(plugin.Description), query) ||
			containsTag(plugin.Tags, query) {
			results = append(results, plugin)
		}
	}

	return results, nil
}

func containsTag(tags []string, query string) bool {
	for _, tag := range tags {
		if strings.Contains(strings.ToLower(tag), query) {
			return true
		}
	}
	return false
}

func installPlugin(name string) error {
	// Simulate installation process
	time.Sleep(2 * time.Second)
	return nil
}

func uninstallPlugin(name string) error {
	// Simulate uninstallation process
	time.Sleep(1 * time.Second)
	return nil
}

func enablePlugin(name string) error {
	// Simulate enabling plugin
	return nil
}

func disablePlugin(name string) error {
	// Simulate disabling plugin
	return nil
}

func updatePlugin(name string) error {
	// Simulate plugin update
	time.Sleep(1 * time.Second)
	return nil
}
