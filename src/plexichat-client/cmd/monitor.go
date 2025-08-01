package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"plexichat-client/pkg/client"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitoring and analytics",
	Long:  "Real-time monitoring, analytics, and system observation",
}

var monitorSystemCmd = &cobra.Command{
	Use:   "system",
	Short: "Monitor system metrics",
	Long:  "Monitor real-time system metrics and performance",
	RunE:  runMonitorSystem,
}

var monitorChatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Monitor chat activity",
	Long:  "Monitor real-time chat activity and user interactions",
	RunE:  runMonitorChat,
}

var monitorUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Monitor user activity",
	Long:  "Monitor user login/logout and activity patterns",
	RunE:  runMonitorUsers,
}

var monitorAlertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "Monitor alerts and notifications",
	Long:  "Monitor system alerts and security notifications",
	RunE:  runMonitorAlerts,
}

var analyticsCmd = &cobra.Command{
	Use:   "analytics",
	Short: "Analytics and reporting",
	Long:  "Generate analytics reports and insights",
	RunE:  runAnalytics,
}

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "System metrics",
	Long:  "Display detailed system metrics and statistics",
	RunE:  runMetrics,
}

type SystemMetrics struct {
	Timestamp         time.Time `json:"timestamp"`
	CPUUsage          float64   `json:"cpu_usage"`
	MemoryUsage       float64   `json:"memory_usage"`
	DiskUsage         float64   `json:"disk_usage"`
	NetworkIn         int64     `json:"network_in"`
	NetworkOut        int64     `json:"network_out"`
	ActiveConnections int       `json:"active_connections"`
	RequestsPerSecond float64   `json:"requests_per_second"`
	ResponseTime      float64   `json:"avg_response_time"`
	ErrorRate         float64   `json:"error_rate"`
}

type ChatActivity struct {
	Timestamp    time.Time `json:"timestamp"`
	RoomID       int       `json:"room_id"`
	RoomName     string    `json:"room_name"`
	UserID       int       `json:"user_id"`
	Username     string    `json:"username"`
	MessageCount int       `json:"message_count"`
	Activity     string    `json:"activity"`
}

type UserActivity struct {
	Timestamp time.Time `json:"timestamp"`
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
}

type Alert struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	Level        string    `json:"level"`
	Type         string    `json:"type"`
	Message      string    `json:"message"`
	Source       string    `json:"source"`
	Acknowledged bool      `json:"acknowledged"`
}

func init() {
	rootCmd.AddCommand(monitorCmd)
	rootCmd.AddCommand(analyticsCmd)
	rootCmd.AddCommand(metricsCmd)

	monitorCmd.AddCommand(monitorSystemCmd)
	monitorCmd.AddCommand(monitorChatCmd)
	monitorCmd.AddCommand(monitorUsersCmd)
	monitorCmd.AddCommand(monitorAlertsCmd)

	// Monitor flags
	monitorSystemCmd.Flags().StringP("interval", "i", "5s", "Refresh interval")
	monitorSystemCmd.Flags().Bool("json", false, "Output in JSON format")
	monitorChatCmd.Flags().IntP("room", "r", 0, "Monitor specific room (0 = all rooms)")
	monitorUsersCmd.Flags().StringP("user", "u", "", "Monitor specific user")
	monitorAlertsCmd.Flags().String("level", "", "Filter by alert level (info, warning, error, critical)")

	// Analytics flags
	analyticsCmd.Flags().StringP("period", "p", "24h", "Analysis period (1h, 24h, 7d, 30d)")
	analyticsCmd.Flags().StringP("format", "f", "table", "Output format (table, json, csv)")
	analyticsCmd.Flags().StringP("output", "o", "", "Output file path")

	// Metrics flags
	metricsCmd.Flags().Bool("detailed", false, "Show detailed metrics")
	metricsCmd.Flags().String("category", "", "Filter by category (system, chat, users, security)")
}

func runMonitorSystem(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	intervalStr, _ := cmd.Flags().GetString("interval")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		return fmt.Errorf("invalid interval: %w", err)
	}

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	color.Cyan("🔍 System Monitoring Started")
	fmt.Printf("Refresh interval: %s (Press Ctrl+C to stop)\n", interval)
	fmt.Println()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-sigChan:
			color.Green("\n👋 Monitoring stopped")
			return nil
		case <-ticker.C:
			err := displaySystemMetrics(c, jsonOutput)
			if err != nil {
				color.Red("Error getting metrics: %v", err)
			}
		}
	}
}

func runMonitorChat(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	roomID, _ := cmd.Flags().GetInt("room")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	color.Cyan("💬 Chat Activity Monitoring Started")
	if roomID > 0 {
		fmt.Printf("Monitoring room: %d\n", roomID)
	} else {
		fmt.Println("Monitoring all rooms")
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Set up WebSocket connection for real-time monitoring
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	endpoint := "/ws/monitor/chat"
	if roomID > 0 {
		endpoint = fmt.Sprintf("/ws/monitor/chat/room/%d", roomID)
	}

	conn, err := c.ConnectWebSocket(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to monitoring WebSocket: %w", err)
	}
	defer conn.Close()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			var activity ChatActivity
			err := conn.ReadJSON(&activity)
			if err != nil {
				color.Red("WebSocket error: %v", err)
				cancel()
				return
			}

			timestamp := activity.Timestamp.Format("15:04:05")
			switch activity.Activity {
			case "message":
				color.Green("[%s] 💬 %s sent message in %s", timestamp, activity.Username, activity.RoomName)
			case "join":
				color.Blue("[%s] 👋 %s joined %s", timestamp, activity.Username, activity.RoomName)
			case "leave":
				color.Yellow("[%s] 👋 %s left %s", timestamp, activity.Username, activity.RoomName)
			case "typing":
				color.Cyan("[%s] ✏️  %s is typing in %s", timestamp, activity.Username, activity.RoomName)
			}
		}
	}()

	<-sigChan
	color.Green("\n👋 Chat monitoring stopped")
	return nil
}

func runMonitorUsers(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	specificUser, _ := cmd.Flags().GetString("user")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	color.Cyan("👥 User Activity Monitoring Started")
	if specificUser != "" {
		fmt.Printf("Monitoring user: %s\n", specificUser)
	} else {
		fmt.Println("Monitoring all users")
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Set up WebSocket connection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	endpoint := "/ws/monitor/users"
	if specificUser != "" {
		endpoint = fmt.Sprintf("/ws/monitor/users/%s", specificUser)
	}

	conn, err := c.ConnectWebSocket(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to user monitoring WebSocket: %w", err)
	}
	defer conn.Close()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			var activity UserActivity
			err := conn.ReadJSON(&activity)
			if err != nil {
				color.Red("WebSocket error: %v", err)
				cancel()
				return
			}

			timestamp := activity.Timestamp.Format("15:04:05")
			switch activity.Action {
			case "login":
				color.Green("[%s] 🔐 %s logged in from %s", timestamp, activity.Username, activity.IPAddress)
			case "logout":
				color.Yellow("[%s] 🚪 %s logged out", timestamp, activity.Username)
			case "failed_login":
				color.Red("[%s] ❌ Failed login attempt for %s from %s", timestamp, activity.Username, activity.IPAddress)
			case "password_change":
				color.Blue("[%s] 🔑 %s changed password", timestamp, activity.Username)
			case "profile_update":
				color.Cyan("[%s] ✏️  %s updated profile", timestamp, activity.Username)
			}
		}
	}()

	<-sigChan
	color.Green("\n👋 User monitoring stopped")
	return nil
}

func runMonitorAlerts(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	level, _ := cmd.Flags().GetString("level")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	color.Cyan("🚨 Alert Monitoring Started")
	if level != "" {
		fmt.Printf("Filtering by level: %s\n", level)
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Set up WebSocket connection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	endpoint := "/ws/monitor/alerts"
	if level != "" {
		endpoint = fmt.Sprintf("/ws/monitor/alerts?level=%s", level)
	}

	conn, err := c.ConnectWebSocket(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to alerts WebSocket: %w", err)
	}
	defer conn.Close()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			var alert Alert
			err := conn.ReadJSON(&alert)
			if err != nil {
				color.Red("WebSocket error: %v", err)
				cancel()
				return
			}

			timestamp := alert.Timestamp.Format("15:04:05")

			var levelColor func(format string, a ...interface{}) string
			var icon string

			switch alert.Level {
			case "critical":
				levelColor = color.RedString
				icon = "🔥"
			case "error":
				levelColor = color.RedString
				icon = "❌"
			case "warning":
				levelColor = color.YellowString
				icon = "⚠️"
			case "info":
				levelColor = color.BlueString
				icon = "ℹ️"
			default:
				levelColor = color.WhiteString
				icon = "📢"
			}

			fmt.Printf("[%s] %s %s [%s] %s - %s\n",
				timestamp,
				icon,
				levelColor(alert.Level),
				alert.Source,
				alert.Type,
				alert.Message)
		}
	}()

	<-sigChan
	color.Green("\n👋 Alert monitoring stopped")
	return nil
}

func runAnalytics(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	period, _ := cmd.Flags().GetString("period")
	format, _ := cmd.Flags().GetString("format")
	outputPath, _ := cmd.Flags().GetString("output")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	color.Cyan("📊 Generating Analytics Report")
	fmt.Printf("Period: %s\n", period)
	fmt.Printf("Format: %s\n", format)
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Request analytics data
	endpoint := fmt.Sprintf("/api/v1/analytics?period=%s&format=%s", period, format)
	resp, err := c.Get(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to get analytics: %w", err)
	}

	var analytics map[string]interface{}
	err = c.ParseResponse(resp, &analytics)
	if err != nil {
		return fmt.Errorf("failed to parse analytics: %w", err)
	}

	// Display or save analytics
	if outputPath != "" {
		data, _ := json.MarshalIndent(analytics, "", "  ")
		err = os.WriteFile(outputPath, data, 0644)
		if err != nil {
			return fmt.Errorf("failed to save analytics: %w", err)
		}
		color.Green("✓ Analytics saved to: %s", outputPath)
	} else {
		displayAnalytics(analytics, format)
	}

	return nil
}

func runMetrics(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	detailed, _ := cmd.Flags().GetBool("detailed")
	category, _ := cmd.Flags().GetString("category")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	endpoint := "/api/v1/metrics"
	if category != "" {
		endpoint += "?category=" + category
	}

	resp, err := c.Get(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to get metrics: %w", err)
	}

	var metrics map[string]interface{}
	err = c.ParseResponse(resp, &metrics)
	if err != nil {
		return fmt.Errorf("failed to parse metrics: %w", err)
	}

	displayMetrics(metrics, detailed)
	return nil
}

func displaySystemMetrics(c *client.Client, jsonOutput bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.Get(ctx, "/api/v1/admin/stats")
	if err != nil {
		return err
	}

	var stats client.AdminStats
	err = c.ParseResponse(resp, &stats)
	if err != nil {
		return err
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(stats, "", "  ")
		fmt.Println(string(data))
	} else {
		// Clear screen and display metrics
		fmt.Print("\033[2J\033[H")

		color.Cyan("=== System Metrics ===")
		fmt.Printf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
		fmt.Printf("Memory Usage: %.2f MB\n", stats.MemoryUsage)
		fmt.Printf("CPU Usage: %.2f%%\n", stats.CPUUsage)
		fmt.Printf("Disk Usage: %.2f%%\n", stats.DiskUsage)
		fmt.Printf("Active Connections: %d\n", stats.ActiveConnections)
		fmt.Printf("Total Users: %d\n", stats.TotalUsers)
		fmt.Printf("Active Users: %d\n", stats.ActiveUsers)
		fmt.Printf("Total Messages: %d\n", stats.TotalMessages)
		fmt.Printf("System Uptime: %s\n", stats.SystemUptime)
	}

	return nil
}

func displayAnalytics(analytics map[string]interface{}, format string) {
	switch format {
	case "json":
		data, _ := json.MarshalIndent(analytics, "", "  ")
		fmt.Println(string(data))
	case "table":
		color.Cyan("Analytics Summary:")
		for key, value := range analytics {
			fmt.Printf("%s: %v\n", key, value)
		}
	default:
		fmt.Printf("%+v\n", analytics)
	}
}

func displayMetrics(metrics map[string]interface{}, detailed bool) {
	color.Cyan("System Metrics:")
	fmt.Println("===============")

	for category, data := range metrics {
		color.Yellow("%s:", category)
		if detailed {
			if categoryData, ok := data.(map[string]interface{}); ok {
				for key, value := range categoryData {
					fmt.Printf("  %s: %v\n", key, value)
				}
			} else {
				fmt.Printf("  %v\n", data)
			}
		} else {
			fmt.Printf("  %v\n", data)
		}
		fmt.Println()
	}
}
