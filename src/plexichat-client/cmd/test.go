package cmd

import (
	"context"
	"fmt"
	"strings"
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
	Name     string
	Tests    []TestResult
	Passed   int
	Failed   int
	Total    int
	Duration time.Duration
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.AddCommand(testAllCmd)
	testCmd.AddCommand(testStressCmd)

	// Test flags
	testAllCmd.Flags().Bool("verbose", false, "Verbose test output")
	testAllCmd.Flags().String("username", "", "Test username")
	testAllCmd.Flags().String("password", "", "Test password")
	testAllCmd.Flags().String("test-file", "", "Path to test file for file upload tests")
	testAllCmd.Flags().Int("room", 1, "Test room ID for chat tests")
	testAllCmd.Flags().Int("messages", 5, "Number of test messages for chat tests")
	testStressCmd.Flags().Int("concurrent", 10, "Number of concurrent connections")
	testStressCmd.Flags().String("duration", "30s", "Test duration")
}

func runTestAll(cmd *cobra.Command, args []string) error {
	verbose, _ := cmd.Flags().GetBool("verbose")
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	testFile, _ := cmd.Flags().GetString("test-file")
	roomID, _ := cmd.Flags().GetInt("room")
	messageCount, _ := cmd.Flags().GetInt("messages")

	if username == "" || password == "" {
		return fmt.Errorf("username and password are required for all tests")
	}

	color.Cyan("🧪 Running Complete Test Suite")
	fmt.Println("===============================")

	allSuites := []*TestSuite{}

	// Run all test suites
	suites := []func() *TestSuite{
		runConnectionTests,
		func() *TestSuite { return runAuthTests(username, password) },
		func() *TestSuite { return runChatTests(username, password, roomID, messageCount) },
		func() *TestSuite { return runFilesTests(username, password, testFile) },
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
	avgDuration := time.Duration(0)
	if totalRequests > 0 {
		avgDuration = totalDuration / time.Duration(totalRequests)
	}
	successRate := 0.0
	if totalRequests > 0 {
		successRate = float64(successfulRequests) / float64(totalRequests) * 100
	}
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
	} else {
		suite.Failed++
	}
}

func (suite *TestSuite) printResults() {
	color.Cyan("%s Results", suite.Name)
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
		color.Green("✅ All tests in this suite passed!")
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

func runAuthTests(username, password string) *TestSuite {
	c := client.NewClient(viper.GetString("url"))
	suite := &TestSuite{Name: "Authentication Tests"}

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

	suite.runTest("Invalid Credentials", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := c.Login(ctx, "invalid", "invalid")
		if err != nil {
			return nil // Expected error
		}
		return fmt.Errorf("expected authentication failure")
	})

	return suite
}

func runChatTests(username, password string, roomID int, messageCount int) *TestSuite {
	c := client.NewClient(viper.GetString("url"))
	suite := &TestSuite{Name: "Chat Tests"}

	// Login to get a token
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	loginResp, err := c.Login(ctx, username, password)
	cancel()
	if err != nil {
		suite.runTest("Login", func() error { return err })
		return suite
	}
	c.SetToken(loginResp.Token)

	suite.runTest("Get Rooms", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := c.GetRooms(ctx, 10, 1)
		return err
	})

	suite.runTest(fmt.Sprintf("Send %d Messages", messageCount), func() error {
		for i := 0; i < messageCount; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			message := fmt.Sprintf("Test message %d from client test", i+1)
			_, err := c.SendMessage(ctx, message, roomID)
			cancel()
			if err != nil {
				return fmt.Errorf("failed to send message %d: %w", i+1, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		return nil
	})

	suite.runTest("Get Message History", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := c.GetMessages(ctx, roomID, 20, 1)
		return err
	})

	suite.runTest("WebSocket Connection", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		conn, err := c.ConnectWebSocket(ctx, "/ws/chat")
		if err != nil {
			return err
		}
		defer conn.Close()
		err = conn.WriteMessage(1, []byte("ping"))
		return err
	})

	return suite
}

func runFilesTests(username, password, testFile string) *TestSuite {
	c := client.NewClient(viper.GetString("url"))
	suite := &TestSuite{Name: "File Tests"}

	// Login to get a token
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	loginResp, err := c.Login(ctx, username, password)
	cancel()
	if err != nil {
		suite.runTest("Login", func() error { return err })
		return suite
	}
	c.SetToken(loginResp.Token)

	suite.runTest("List Files", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := c.GetFiles(ctx, 10, 1, "")
		return err
	})

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

		suite.runTest("Get File Info", func() error {
			if uploadedFileID == 0 {
				return fmt.Errorf("no uploaded file ID")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := c.GetFileInfo(ctx, uploadedFileID)
			return err
		})

		suite.runTest("Delete File", func() error {
			if uploadedFileID == 0 {
				return fmt.Errorf("no uploaded file ID")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return c.DeleteFile(ctx, uploadedFileID)
		})
	}

	return suite
}

func runPerformanceTests() *TestSuite {
	c := client.NewClient(viper.GetString("url"))
	suite := &TestSuite{Name: "Performance Tests"}

	suite.runTest("Response Time < 500ms", func() error {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := c.Health(ctx)
		duration := time.Since(start)
		if err != nil {
			return err
		}
		if duration > 500*time.Millisecond {
			return fmt.Errorf("response time %s exceeds 500ms", duration)
		}
		return nil
	})

	return suite
}
