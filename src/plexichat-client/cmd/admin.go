package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"plexichat-client/pkg/client"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Admin commands",
	Long:  "Administrative commands for managing users, system settings, and monitoring",
}

var adminUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "User management",
	Long:  "Commands for managing users",
}

var adminUsersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users",
	Long:  "List all users in the system",
	RunE:  runAdminUsersList,
}

var adminStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "System statistics",
	Long:  "Display system statistics and monitoring information",
	RunE:  runAdminStats,
}

var adminConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management",
	Long:  "Manage system configuration settings",
}

var adminConfigRateLimitCmd = &cobra.Command{
	Use:   "rate-limit",
	Short: "Configure rate limiting",
	Long:  "Configure rate limiting settings",
	RunE:  runAdminConfigRateLimit,
}

var adminConfigSecurityCmd = &cobra.Command{
	Use:   "security",
	Short: "Configure security settings",
	Long:  "Configure security settings",
	RunE:  runAdminConfigSecurity,
}

func init() {
	rootCmd.AddCommand(adminCmd)
	adminCmd.AddCommand(adminUsersCmd)
	adminCmd.AddCommand(adminStatsCmd)
	adminCmd.AddCommand(adminConfigCmd)
	
	adminUsersCmd.AddCommand(adminUsersListCmd)
	adminConfigCmd.AddCommand(adminConfigRateLimitCmd)
	adminConfigCmd.AddCommand(adminConfigSecurityCmd)

	// Users list flags
	adminUsersListCmd.Flags().IntP("limit", "l", 50, "Number of users to retrieve")
	adminUsersListCmd.Flags().IntP("page", "p", 1, "Page number")
	adminUsersListCmd.Flags().String("type", "", "Filter by user type (user, bot, admin)")

	// Rate limit config flags
	adminConfigRateLimitCmd.Flags().Int("requests-per-minute", 0, "Requests per minute limit")
	adminConfigRateLimitCmd.Flags().Int("burst-limit", 0, "Burst limit")
	adminConfigRateLimitCmd.Flags().Int("user-requests", 0, "User requests per minute")
	adminConfigRateLimitCmd.Flags().Int("bot-requests", 0, "Bot requests per minute")
	adminConfigRateLimitCmd.Flags().Int("admin-requests", 0, "Admin requests per minute")
	adminConfigRateLimitCmd.Flags().Bool("enable", false, "Enable rate limiting")
	adminConfigRateLimitCmd.Flags().Bool("disable", false, "Disable rate limiting")

	// Security config flags
	adminConfigSecurityCmd.Flags().Int("max-login-attempts", 0, "Maximum login attempts")
	adminConfigSecurityCmd.Flags().String("lockout-duration", "", "Lockout duration (e.g., 15m)")
	adminConfigSecurityCmd.Flags().Int("password-min-length", 0, "Minimum password length")
	adminConfigSecurityCmd.Flags().String("session-timeout", "", "Session timeout (e.g., 30m)")
	adminConfigSecurityCmd.Flags().Bool("require-https", false, "Require HTTPS")
	adminConfigSecurityCmd.Flags().Bool("enable-ip-blacklist", false, "Enable IP blacklist")
	adminConfigSecurityCmd.Flags().Bool("enable-threat-detection", false, "Enable threat detection")
}

func runAdminUsersList(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	limit, _ := cmd.Flags().GetInt("limit")
	page, _ := cmd.Flags().GetInt("page")
	userType, _ := cmd.Flags().GetString("type")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	endpoint := fmt.Sprintf("/api/v1/admin/users?limit=%d&page=%d", limit, page)
	if userType != "" {
		endpoint += "&type=" + userType
	}

	resp, err := c.Get(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to get users: %w", err)
	}

	var listResp client.ListResponse
	err = c.ParseResponse(resp, &listResp)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Parse users
	usersData, _ := json.Marshal(listResp.Items)
	var users []client.User
	json.Unmarshal(usersData, &users)

	if len(users) == 0 {
		fmt.Println("No users found.")
		return nil
	}

	// Display users in a table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Username", "Email", "Type", "Active", "Admin", "Created"})
	table.SetBorder(false)
	table.SetRowSeparator("-")
	table.SetColumnSeparator("|")
	table.SetCenterSeparator("+")

	for _, user := range users {
		active := "No"
		if user.IsActive {
			active = "Yes"
		}
		
		admin := "No"
		if user.IsAdmin {
			admin = "Yes"
		}
		
		table.Append([]string{
			strconv.Itoa(user.ID),
			user.Username,
			user.Email,
			user.UserType,
			active,
			admin,
			user.Created,
		})
	}

	fmt.Printf("Users (Page %d of %d)\n", page, listResp.TotalPages)
	table.Render()
	fmt.Printf("Total users: %d\n", listResp.Total)

	return nil
}

func runAdminStats(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.Get(ctx, "/api/v1/admin/stats")
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	var stats client.AdminStats
	err = c.ParseResponse(resp, &stats)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Display stats
	color.Cyan("=== System Statistics ===")
	fmt.Printf("Total Users: %d\n", stats.TotalUsers)
	fmt.Printf("Active Users: %d\n", stats.ActiveUsers)
	fmt.Printf("Total Messages: %d\n", stats.TotalMessages)
	fmt.Printf("Total Rooms: %d\n", stats.TotalRooms)
	fmt.Printf("Total Files: %d\n", stats.TotalFiles)
	fmt.Printf("System Uptime: %s\n", stats.SystemUptime)
	
	color.Cyan("\n=== Resource Usage ===")
	fmt.Printf("Memory Usage: %.2f MB\n", stats.MemoryUsage)
	fmt.Printf("CPU Usage: %.2f%%\n", stats.CPUUsage)
	fmt.Printf("Disk Usage: %.2f%%\n", stats.DiskUsage)
	fmt.Printf("Active Connections: %d\n", stats.ActiveConnections)

	return nil
}

func runAdminConfigRateLimit(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build configuration object
	config := client.RateLimitConfig{}
	
	if cmd.Flags().Changed("enable") {
		config.Enabled = true
	}
	if cmd.Flags().Changed("disable") {
		config.Enabled = false
	}
	if cmd.Flags().Changed("requests-per-minute") {
		config.RequestsPerMinute, _ = cmd.Flags().GetInt("requests-per-minute")
	}
	if cmd.Flags().Changed("burst-limit") {
		config.BurstLimit, _ = cmd.Flags().GetInt("burst-limit")
	}
	if cmd.Flags().Changed("user-requests") {
		config.UserRequestsPerMin, _ = cmd.Flags().GetInt("user-requests")
	}
	if cmd.Flags().Changed("bot-requests") {
		config.BotRequestsPerMin, _ = cmd.Flags().GetInt("bot-requests")
	}
	if cmd.Flags().Changed("admin-requests") {
		config.AdminRequestsPerMin, _ = cmd.Flags().GetInt("admin-requests")
	}

	resp, err := c.Put(ctx, "/api/v1/admin/config/rate-limit", config)
	if err != nil {
		return fmt.Errorf("failed to update rate limit config: %w", err)
	}

	var updatedConfig client.RateLimitConfig
	err = c.ParseResponse(resp, &updatedConfig)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	color.Green("✓ Rate limit configuration updated successfully!")
	fmt.Printf("Enabled: %t\n", updatedConfig.Enabled)
	fmt.Printf("Requests per minute: %d\n", updatedConfig.RequestsPerMinute)
	fmt.Printf("Burst limit: %d\n", updatedConfig.BurstLimit)
	fmt.Printf("User requests per minute: %d\n", updatedConfig.UserRequestsPerMin)
	fmt.Printf("Bot requests per minute: %d\n", updatedConfig.BotRequestsPerMin)
	fmt.Printf("Admin requests per minute: %d\n", updatedConfig.AdminRequestsPerMin)

	return nil
}

func runAdminConfigSecurity(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build configuration object
	config := client.SecurityConfig{}
	
	if cmd.Flags().Changed("max-login-attempts") {
		config.MaxLoginAttempts, _ = cmd.Flags().GetInt("max-login-attempts")
	}
	if cmd.Flags().Changed("lockout-duration") {
		config.LockoutDuration, _ = cmd.Flags().GetString("lockout-duration")
	}
	if cmd.Flags().Changed("password-min-length") {
		config.PasswordMinLength, _ = cmd.Flags().GetInt("password-min-length")
	}
	if cmd.Flags().Changed("session-timeout") {
		config.SessionTimeout, _ = cmd.Flags().GetString("session-timeout")
	}
	if cmd.Flags().Changed("require-https") {
		config.RequireHTTPS, _ = cmd.Flags().GetBool("require-https")
	}
	if cmd.Flags().Changed("enable-ip-blacklist") {
		config.EnableIPBlacklist, _ = cmd.Flags().GetBool("enable-ip-blacklist")
	}
	if cmd.Flags().Changed("enable-threat-detection") {
		config.EnableThreatDetect, _ = cmd.Flags().GetBool("enable-threat-detection")
	}

	resp, err := c.Put(ctx, "/api/v1/admin/config/security", config)
	if err != nil {
		return fmt.Errorf("failed to update security config: %w", err)
	}

	var updatedConfig client.SecurityConfig
	err = c.ParseResponse(resp, &updatedConfig)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	color.Green("✓ Security configuration updated successfully!")
	fmt.Printf("Require HTTPS: %t\n", updatedConfig.RequireHTTPS)
	fmt.Printf("Max login attempts: %d\n", updatedConfig.MaxLoginAttempts)
	fmt.Printf("Lockout duration: %s\n", updatedConfig.LockoutDuration)
	fmt.Printf("Password min length: %d\n", updatedConfig.PasswordMinLength)
	fmt.Printf("Session timeout: %s\n", updatedConfig.SessionTimeout)
	fmt.Printf("IP blacklist enabled: %t\n", updatedConfig.EnableIPBlacklist)
	fmt.Printf("Threat detection enabled: %t\n", updatedConfig.EnableThreatDetect)

	return nil
}
