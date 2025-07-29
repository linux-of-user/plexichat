package cmd

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"plexichat-client/pkg/client"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Testing framework",
	Long:  "Comprehensive testing framework for PlexiChat functionality",
}

var testConnectionCmd = &cobra.Command{
	Use:   "connection",
	Short: "Test connection to server",
	Long:  "Test basic connectivity to PlexiChat server",
	RunE:  runTestConnection,
}

var testAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Test authentication",
	Long:  "Test authentication functionality",
	RunE:  runTestAuth,
}

var testChatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Test chat functionality",
	Long:  "Test chat messaging and real-time features",
	RunE:  runTestChat,
}

var testFilesCmd = &cobra.Command{
	Use:   "files",
	Short: "Test file operations",
	Long:  "Test file upload, download, and management",
	RunE:  runTestFiles,
}

var testAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Run all tests",
	Long:  "Run comprehensive test suite",
	RunE:  runTestAll,
}

var testStressCmd = &cobra.Command{
	Use:   "stress",
	Short: "Stress testing",
	Long:  "Run stress tests with high load",
	RunE:  runTestStress,
}

type TestResult struct {
	Name     string
	Passed   bool
	Duration time.Duration
	Error    error
	Details  string
}

type TestSuite struct {
	Name    string
	Tests   []TestResult
	Passed  int
	Failed  int
	Total   int
	Duration time.Duration
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.AddCommand(testConnectionCmd)
	testCmd.AddCommand(testAuthCmd)
	testCmd.AddCommand(testChatCmd)
	testCmd.AddCommand(testFilesCmd)
	testCmd.AddCommand(testAllCmd)
	testCmd.AddCommand(testStressCmd)

	// Test flags
	testConnectionCmd.Flags().Int("timeout", 10, "Connection timeout in seconds")
	testAuthCmd.Flags().String("username", "", "Test username")
	testAuthCmd.Flags().String("password", "", "Test password")
	testChatCmd.Flags().Int("room", 1, "Test room ID")
	testChatCmd.Flags().Int("messages", 5, "Number of test messages")
	testFilesCmd.Flags().String("test-file", "", "Path to test file")
	testAllCmd.Flags().Bool("verbose", false, "Verbose test output")
	testStressCmd.Flags().Int("concurrent", 10, "Number of concurrent connections")
	testStressCmd.Flags().String("duration", "30s", "Test duration")
}

func runTestConnection(cmd *cobra.Command, args []string) error {
	timeout, _ := cmd.Flags().GetInt("timeout")

	color.Cyan("🔗 Testing Connection")
	fmt.Println("===================")

	c := client.NewClient(viper.GetString("url"))
	
	suite := &TestSuite{Name: "Connection Tests"}
	
	// Test 1: Health check
	suite.runTest("Health Check", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()
		
		_, err := c.Health(ctx)
		return err
	})
	
	// Test 2: Version check
	suite.runTest("Version Check", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()
		
		_, err := c.Version(ctx)
		return err
	})
	
	// Test 3: Invalid endpoint
	suite.runTest("Invalid Endpoint Handling", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()
		
		resp, err := c.Get(ctx, "/invalid/endpoint")
		if err != nil {
			return nil // Expected error
		}
		if resp.StatusCode == 404 {
			return nil // Expected 404
		}
		return fmt.Errorf("expected error or 404, got status %d", resp.StatusCode)
	})

	suite.printResults()
	return nil
}

func runTestAuth(cmd *cobra.Command, args []string) error {
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")

	if username == "" || password == "" {
		return fmt.Errorf("username and password are required for auth tests")
	}

	color.Cyan("🔐 Testing Authentication")
	fmt.Println("========================")

	c := client.NewClient(viper.GetString("url"))
	
	suite := &TestSuite{Name: "Authentication Tests"}
	
	// Test 1: Valid login
	var token string
	suite.runTest("Valid Login", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		loginResp, err := c.Login(ctx, username, password)
		if err != nil {
			return err
		}
		token = loginResp.Token
		return nil
	})
	
	// Test 2: Get current user
	suite.runTest("Get Current User", func() error {
		if token == "" {
			return fmt.Errorf("no token available")
		}
		
		c.SetToken(token)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		_, err := c.GetCurrentUser(ctx)
		return err
	})
	
	// Test 3: Invalid credentials
	suite.runTest("Invalid Credentials", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		_, err := c.Login(ctx, "invalid", "invalid")
		if err != nil {
			return nil // Expected error
		}
		return fmt.Errorf("expected authentication failure")
	})

	suite.printResults()
	return nil
}

func runTestChat(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	roomID, _ := cmd.Flags().GetInt("room")
	messageCount, _ := cmd.Flags().GetInt("messages")

	color.Cyan("💬 Testing Chat Functionality")
	fmt.Println("=============================")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)
	
	suite := &TestSuite{Name: "Chat Tests"}
	
	// Test 1: Get rooms
	suite.runTest("Get Rooms", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		_, err := c.GetRooms(ctx, 10, 1)
		return err
	})
	
	// Test 2: Send messages
	suite.runTest(fmt.Sprintf("Send %d Messages", messageCount), func() error {
		for i := 0; i < messageCount; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			
			message := fmt.Sprintf("Test message %d from client test", i+1)
			_, err := c.SendMessage(ctx, message, roomID)
			cancel()
			
			if err != nil {
				return fmt.Errorf("failed to send message %d: %w", i+1, err)
			}
			
			time.Sleep(100 * time.Millisecond) // Small delay between messages
		}
		return nil
	})
	
	// Test 3: Get message history
	suite.runTest("Get Message History", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		_, err := c.GetMessages(ctx, roomID, 20, 1)
		return err
	})
	
	// Test 4: WebSocket connection
	suite.runTest("WebSocket Connection", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		conn, err := c.ConnectWebSocket(ctx, "/ws/chat")
		if err != nil {
			return err
		}
		defer conn.Close()
		
		// Test sending a ping
		err = conn.WriteMessage(1, []byte("ping"))
		return err
	})

	suite.printResults()
	return nil
}

func runTestFiles(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	testFile, _ := cmd.Flags().GetString("test-file")

	color.Cyan("📁 Testing File Operations")
	fmt.Println("==========================")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)
	
	suite := &TestSuite{Name: "File Tests"}
	
	// Test 1: List files
	suite.runTest("List Files", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		_, err := c.GetFiles(ctx, 10, 1, "")
		return err
	})
	
	// Test 2: Upload file (if test file provided)
	var uploadedFileID int
	if testFile != "" {
		suite.runTest("Upload File", func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			
			resp, err := c.UploadFile(ctx, "/api/v1/files", testFile)
			if err != nil {
				return err
			}
			
			var file client.File
			err = c.ParseResponse(resp, &file)
			if err != nil {
				return err
			}
			
			uploadedFileID = file.ID
			return nil
		})
		
		// Test 3: Get file info
		suite.runTest("Get File Info", func() error {
			if uploadedFileID == 0 {
				return fmt.Errorf("no uploaded file ID")
			}
			
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			
			_, err := c.GetFileInfo(ctx, uploadedFileID)
			return err
		})
		
		// Test 4: Delete file
		suite.runTest("Delete File", func() error {
			if uploadedFileID == 0 {
				return fmt.Errorf("no uploaded file ID")
			}
			
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			
			return c.DeleteFile(ctx, uploadedFileID)
		})
	}

	suite.printResults()
	return nil
}

func runTestAll(cmd *cobra.Command, args []string) error {
	verbose, _ := cmd.Flags().GetBool("verbose")

	color.Cyan("🧪 Running Complete Test Suite")
	fmt.Println("==============================")

	allSuites := []*TestSuite{}
	
	// Run all test suites
	suites := []func() *TestSuite{
		runConnectionTests,
		runBasicAPITests,
		runPerformanceTests,
	}
	
	for _, suiteFunc := range suites {
		suite := suiteFunc()
		allSuites = append(allSuites, suite)
		
		if verbose {
			suite.printResults()
			fmt.Println()
		}
	}
	
	// Print summary
	color.Cyan("Test Summary")
	fmt.Println("============")
	
	totalPassed := 0
	totalFailed := 0
	totalTests := 0
	
	for _, suite := range allSuites {
		fmt.Printf("%s: %d/%d passed\n", suite.Name, suite.Passed, suite.Total)
		totalPassed += suite.Passed
		totalFailed += suite.Failed
		totalTests += suite.Total
	}
	
	fmt.Printf("\nOverall: %d/%d tests passed\n", totalPassed, totalTests)
	
	if totalFailed > 0 {
		color.Red("❌ %d tests failed", totalFailed)
		return fmt.Errorf("test suite failed")
	} else {
		color.Green("✅ All tests passed!")
	}
	
	return nil
}

func runTestStress(cmd *cobra.Command, args []string) error {
	concurrent, _ := cmd.Flags().GetInt("concurrent")
	durationStr, _ := cmd.Flags().GetString("duration")

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}

	color.Cyan("⚡ Running Stress Tests")
	fmt.Printf("Concurrent connections: %d\n", concurrent)
	fmt.Printf("Duration: %s\n", duration)
	fmt.Println("======================")

	var wg sync.WaitGroup
	results := make(chan TestResult, concurrent*100)
	
	startTime := time.Now()
	endTime := startTime.Add(duration)
	
	// Start concurrent workers
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			c := client.NewClient(viper.GetString("url"))
			requestCount := 0
			
			for time.Now().Before(endTime) {
				start := time.Now()
				
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, err := c.Health(ctx)
				cancel()
				
				elapsed := time.Since(start)
				requestCount++
				
				results <- TestResult{
					Name:     fmt.Sprintf("Worker-%d-Request-%d", workerID, requestCount),
					Passed:   err == nil,
					Duration: elapsed,
					Error:    err,
				}
				
				time.Sleep(10 * time.Millisecond) // Small delay
			}
		}(i)
	}
	
	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Collect results
	var allResults []TestResult
	for result := range results {
		allResults = append(allResults, result)
	}
	
	// Analyze results
	totalRequests := len(allResults)
	successfulRequests := 0
	var totalDuration time.Duration
	var minDuration, maxDuration time.Duration
	
	if totalRequests > 0 {
		minDuration = allResults[0].Duration
		maxDuration = allResults[0].Duration
	}
	
	for _, result := range allResults {
		if result.Passed {
			successfulRequests++
		}
		totalDuration += result.Duration
		
		if result.Duration < minDuration {
			minDuration = result.Duration
		}
		if result.Duration > maxDuration {
			maxDuration = result.Duration
		}
	}
	
	actualDuration := time.Since(startTime)
	avgDuration := totalDuration / time.Duration(totalRequests)
	successRate := float64(successfulRequests) / float64(totalRequests) * 100
	requestsPerSecond := float64(totalRequests) / actualDuration.Seconds()
	
	// Print results
	color.Cyan("Stress Test Results")
	fmt.Println("==================")
	fmt.Printf("Total Requests: %d\n", totalRequests)
	fmt.Printf("Successful: %d\n", successfulRequests)
	fmt.Printf("Failed: %d\n", totalRequests-successfulRequests)
	fmt.Printf("Success Rate: %.2f%%\n", successRate)
	fmt.Printf("Requests/sec: %.2f\n", requestsPerSecond)
	fmt.Printf("Avg Response Time: %s\n", avgDuration)
	fmt.Printf("Min Response Time: %s\n", minDuration)
	fmt.Printf("Max Response Time: %s\n", maxDuration)
	fmt.Printf("Test Duration: %s\n", actualDuration)
	
	if successRate < 95 {
		color.Red("⚠️  Low success rate detected!")
	} else {
		color.Green("✅ Stress test completed successfully")
	}
	
	return nil
}

// Helper functions

func (suite *TestSuite) runTest(name string, testFunc func() error) {
	start := time.Now()
	err := testFunc()
	duration := time.Since(start)
	
	result := TestResult{
		Name:     name,
		Passed:   err == nil,
		Duration: duration,
		Error:    err,
	}
	
	suite.Tests = append(suite.Tests, result)
	suite.Total++
	
	if result.Passed {
		suite.Passed++
		color.Green("✅ %s (%s)", name, duration)
	} else {
		suite.Failed++
		color.Red("❌ %s (%s): %v", name, duration, err)
	}
}

func (suite *TestSuite) printResults() {
	color.Cyan("\n%s Results", suite.Name)
	fmt.Println(strings.Repeat("=", len(suite.Name)+8))
	
	for _, test := range suite.Tests {
		if test.Passed {
			color.Green("✅ %s (%s)", test.Name, test.Duration)
		} else {
			color.Red("❌ %s (%s): %v", test.Name, test.Duration, test.Error)
		}
	}
	
	fmt.Printf("\nSummary: %d/%d tests passed\n", suite.Passed, suite.Total)
	
	if suite.Failed > 0 {
		color.Red("❌ %d tests failed", suite.Failed)
	} else {
		color.Green("✅ All tests passed!")
	}
}

func runConnectionTests() *TestSuite {
	c := client.NewClient(viper.GetString("url"))
	suite := &TestSuite{Name: "Connection Tests"}
	
	suite.runTest("Health Check", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := c.Health(ctx)
		return err
	})
	
	suite.runTest("Version Check", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := c.Version(ctx)
		return err
	})
	
	return suite
}

func runBasicAPITests() *TestSuite {
	c := client.NewClient(viper.GetString("url"))
	suite := &TestSuite{Name: "Basic API Tests"}
	
	suite.runTest("Invalid Endpoint", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		resp, err := c.Get(ctx, "/invalid")
		if err != nil {
			return nil // Expected
		}
		if resp.StatusCode == 404 {
			return nil // Expected
		}
		return fmt.Errorf("expected 404, got %d", resp.StatusCode)
	})
	
	return suite
}

func runPerformanceTests() *TestSuite {
	c := client.NewClient(viper.GetString("url"))
	suite := &TestSuite{Name: "Performance Tests"}
	
	suite.runTest("Response Time < 100ms", func() error {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		_, err := c.Health(ctx)
		duration := time.Since(start)
		
		if err != nil {
			return err
		}
		
		if duration > 100*time.Millisecond {
			return fmt.Errorf("response time %s exceeds 100ms", duration)
		}
		
		return nil
	})
	
	return suite
}
