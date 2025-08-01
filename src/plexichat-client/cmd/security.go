package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"plexichat-client/pkg/client"
)

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Security testing commands",
	Long:  "Commands for security testing, vulnerability scanning, and penetration testing",
}

var securityTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Run security tests",
	Long:  "Run security tests against PlexiChat endpoints",
	RunE:  runSecurityTest,
}

var securityScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run vulnerability scan",
	Long:  "Run comprehensive vulnerability scan",
	RunE:  runSecurityScan,
}

var securityReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate security report",
	Long:  "Generate comprehensive security assessment report",
	RunE:  runSecurityReport,
}

func init() {
	rootCmd.AddCommand(securityCmd)
	securityCmd.AddCommand(securityTestCmd)
	securityCmd.AddCommand(securityScanCmd)
	securityCmd.AddCommand(securityReportCmd)

	// Test flags
	securityTestCmd.Flags().StringP("endpoint", "e", "", "Endpoint to test")
	securityTestCmd.Flags().StringP("method", "m", "GET", "HTTP method")
	securityTestCmd.Flags().StringP("payload", "p", "", "Test payload")
	securityTestCmd.Flags().StringP("type", "t", "", "Test type (sql_injection, xss, csrf, etc.)")
	securityTestCmd.Flags().Bool("full-scan", false, "Run full security scan")
	securityTestCmd.Flags().StringSlice("headers", []string{}, "Custom headers (key:value)")

	// Scan flags
	securityScanCmd.Flags().StringSlice("endpoints", []string{}, "Specific endpoints to scan")
	securityScanCmd.Flags().Bool("all", false, "Scan all known endpoints")
	securityScanCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	securityScanCmd.Flags().Int("timeout", 30, "Request timeout in seconds")

	// Report flags
	securityReportCmd.Flags().StringP("format", "f", "json", "Report format (json, html, text)")
	securityReportCmd.Flags().StringP("output", "o", "", "Output file path")
	securityReportCmd.Flags().Bool("detailed", false, "Include detailed vulnerability information")
}

func runSecurityTest(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	endpoint, _ := cmd.Flags().GetString("endpoint")
	method, _ := cmd.Flags().GetString("method")
	payload, _ := cmd.Flags().GetString("payload")
	testType, _ := cmd.Flags().GetString("type")
	fullScan, _ := cmd.Flags().GetBool("full-scan")
	headers, _ := cmd.Flags().GetStringSlice("headers")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if fullScan {
		return runFullSecurityScan(c, ctx)
	}

	if endpoint == "" {
		return fmt.Errorf("endpoint is required when not running full scan")
	}

	// Parse headers
	headerMap := make(map[string]string)
	for _, header := range headers {
		// Parse key:value format
		if len(header) > 0 {
			parts := []string{header, ""}
			if len(parts) == 2 {
				headerMap[parts[0]] = parts[1]
			}
		}
	}

	// Create test request
	testReq := &client.SecurityTestRequest{
		Endpoint: endpoint,
		Method:   method,
		Payload:  payload,
		Headers:  headerMap,
		TestType: testType,
	}

	resp, err := c.Post(ctx, "/api/v1/security/test", testReq)
	if err != nil {
		return fmt.Errorf("failed to run security test: %w", err)
	}

	var testResp client.SecurityTestResponse
	err = c.ParseResponse(resp, &testResp)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Display results
	fmt.Printf("Security Test Results\n")
	fmt.Printf("====================\n")
	fmt.Printf("Test ID: %s\n", testResp.TestID)
	fmt.Printf("Endpoint: %s\n", testResp.Endpoint)
	fmt.Printf("Method: %s\n", testResp.Method)
	fmt.Printf("Status Code: %d\n", testResp.StatusCode)
	fmt.Printf("Response Time: %d ms\n", testResp.ResponseTime)

	if testResp.Vulnerable {
		color.Red("⚠️  VULNERABILITY DETECTED!")
		fmt.Printf("Severity: %s\n", testResp.Severity)
		fmt.Printf("Description: %s\n", testResp.Description)
		fmt.Printf("Evidence: %s\n", testResp.Evidence)
		fmt.Printf("Remediation: %s\n", testResp.Remediation)
	} else {
		color.Green("✓ No vulnerabilities detected")
	}

	return nil
}

func runSecurityScan(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	endpoints, _ := cmd.Flags().GetStringSlice("endpoints")
	scanAll, _ := cmd.Flags().GetBool("all")
	severity, _ := cmd.Flags().GetString("severity")
	timeout, _ := cmd.Flags().GetInt("timeout")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	// Build scan request
	scanReq := map[string]interface{}{
		"scan_all":  scanAll,
		"endpoints": endpoints,
		"severity":  severity,
		"timeout":   timeout,
	}

	fmt.Println("Starting vulnerability scan...")

	resp, err := c.Post(ctx, "/api/v1/security/scan", scanReq)
	if err != nil {
		return fmt.Errorf("failed to start security scan: %w", err)
	}

	var scanResults []client.SecurityTestResponse
	err = c.ParseResponse(resp, &scanResults)
	if err != nil {
		return fmt.Errorf("failed to parse scan results: %w", err)
	}

	// Display results in table
	if len(scanResults) == 0 {
		color.Green("✓ No vulnerabilities found!")
		return nil
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Endpoint", "Vulnerability", "Severity", "Status"})
	table.SetBorder(false)
	table.SetRowSeparator("-")
	table.SetColumnSeparator("|")
	table.SetCenterSeparator("+")

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, result := range scanResults {
		status := "SAFE"
		if result.Vulnerable {
			status = "VULNERABLE"
			switch result.Severity {
			case "critical":
				criticalCount++
			case "high":
				highCount++
			case "medium":
				mediumCount++
			case "low":
				lowCount++
			}
		}

		table.Append([]string{
			result.Endpoint,
			result.Description,
			result.Severity,
			status,
		})
	}

	fmt.Printf("\nVulnerability Scan Results\n")
	fmt.Printf("==========================\n")
	table.Render()

	fmt.Printf("\nSummary:\n")
	fmt.Printf("Critical: %d\n", criticalCount)
	fmt.Printf("High: %d\n", highCount)
	fmt.Printf("Medium: %d\n", mediumCount)
	fmt.Printf("Low: %d\n", lowCount)

	if criticalCount > 0 || highCount > 0 {
		color.Red("⚠️  Critical or High severity vulnerabilities found!")
	} else if mediumCount > 0 {
		color.Yellow("⚠️  Medium severity vulnerabilities found")
	} else {
		color.Green("✓ No critical vulnerabilities detected")
	}

	return nil
}

func runSecurityReport(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	format, _ := cmd.Flags().GetString("format")
	outputPath, _ := cmd.Flags().GetString("output")
	detailed, _ := cmd.Flags().GetBool("detailed")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Request report generation
	reportReq := map[string]interface{}{
		"format":   format,
		"detailed": detailed,
	}

	fmt.Println("Generating security report...")

	resp, err := c.Post(ctx, "/api/v1/security/report", reportReq)
	if err != nil {
		return fmt.Errorf("failed to generate security report: %w", err)
	}

	// Get report content
	reportContent := c.ParseResponse(resp, nil)
	if err != nil {
		return fmt.Errorf("failed to get report content: %w", err)
	}

	// Save or display report
	if outputPath != "" {
		err = os.WriteFile(outputPath, []byte(fmt.Sprintf("%v", reportContent)), 0644)
		if err != nil {
			return fmt.Errorf("failed to save report: %w", err)
		}
		color.Green("✓ Security report saved to: %s", outputPath)
	} else {
		fmt.Println(reportContent)
	}

	return nil
}

func runFullSecurityScan(c *client.Client, ctx context.Context) error {
	fmt.Println("Running comprehensive security scan...")

	// Common endpoints to test
	endpoints := []string{
		"/api/v1/auth/login",
		"/api/v1/auth/register",
		"/api/v1/users",
		"/api/v1/messages",
		"/api/v1/files",
		"/api/v1/admin",
		"/health",
		"/docs",
	}

	// Common vulnerability types
	vulnTypes := []string{
		"sql_injection",
		"xss",
		"csrf",
		"directory_traversal",
		"command_injection",
		"authentication_bypass",
		"authorization_bypass",
	}

	allResults := []client.SecurityTestResponse{}

	for _, endpoint := range endpoints {
		for _, vulnType := range vulnTypes {
			testReq := &client.SecurityTestRequest{
				Endpoint: endpoint,
				Method:   "GET",
				TestType: vulnType,
			}

			resp, err := c.Post(ctx, "/api/v1/security/test", testReq)
			if err != nil {
				fmt.Printf("Failed to test %s for %s: %v\n", endpoint, vulnType, err)
				continue
			}

			var testResp client.SecurityTestResponse
			err = c.ParseResponse(resp, &testResp)
			if err != nil {
				fmt.Printf("Failed to parse response for %s: %v\n", endpoint, err)
				continue
			}

			if testResp.Vulnerable {
				allResults = append(allResults, testResp)
			}

			fmt.Printf(".")
		}
	}

	fmt.Printf("\n\nScan Complete!\n")
	fmt.Printf("==============\n")

	if len(allResults) == 0 {
		color.Green("✓ No vulnerabilities found!")
		return nil
	}

	// Display vulnerabilities
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Endpoint", "Type", "Severity", "Description"})
	table.SetBorder(false)

	for _, result := range allResults {
		table.Append([]string{
			result.Endpoint,
			result.TestID,
			result.Severity,
			result.Description,
		})
	}

	table.Render()
	color.Red("⚠️  %d vulnerabilities found!", len(allResults))

	return nil
}
