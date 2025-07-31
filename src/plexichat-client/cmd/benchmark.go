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

var benchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Performance benchmarking commands",
	Long:  "Commands for performance testing, load testing, and response time measurement",
}

var benchmarkLoadCmd = &cobra.Command{
	Use:   "load",
	Short: "Run load test",
	Long:  "Run load test with concurrent users",
	RunE:  runBenchmarkLoad,
}

var benchmarkResponseCmd = &cobra.Command{
	Use:   "response",
	Short: "Test response times",
	Long:  "Test API response times",
	RunE:  runBenchmarkResponse,
}

var benchmarkMicrosecondCmd = &cobra.Command{
	Use:   "microsecond",
	Short: "Microsecond performance test",
	Long:  "Test microsecond-level performance",
	RunE:  runBenchmarkMicrosecond,
}

func init() {
	rootCmd.AddCommand(benchmarkCmd)
	benchmarkCmd.AddCommand(benchmarkLoadCmd)
	benchmarkCmd.AddCommand(benchmarkResponseCmd)
	benchmarkCmd.AddCommand(benchmarkMicrosecondCmd)

	// Load test flags
	benchmarkLoadCmd.Flags().StringP("endpoint", "e", "/api/v1/health", "Endpoint to test")
	benchmarkLoadCmd.Flags().StringP("method", "m", "GET", "HTTP method")
	benchmarkLoadCmd.Flags().IntP("concurrent", "c", 10, "Number of concurrent users")
	benchmarkLoadCmd.Flags().StringP("duration", "d", "30s", "Test duration")
	benchmarkLoadCmd.Flags().Int("requests-per-sec", 0, "Target requests per second (0 = unlimited)")

	// Response time flags
	benchmarkResponseCmd.Flags().StringP("endpoint", "e", "/api/v1/health", "Endpoint to test")
	benchmarkResponseCmd.Flags().StringP("method", "m", "GET", "HTTP method")
	benchmarkResponseCmd.Flags().IntP("samples", "s", 100, "Number of samples")
	benchmarkResponseCmd.Flags().String("target", "1ms", "Target response time")

	// Microsecond test flags
	benchmarkMicrosecondCmd.Flags().StringP("endpoint", "e", "/api/v1/health", "Endpoint to test")
	benchmarkMicrosecondCmd.Flags().IntP("samples", "s", 1000, "Number of samples")
	benchmarkMicrosecondCmd.Flags().Bool("validate", false, "Validate microsecond performance")
}

type BenchmarkResult struct {
	TotalRequests    int64
	SuccessfulReqs   int64
	FailedRequests   int64
	TotalDuration    time.Duration
	MinResponseTime  time.Duration
	MaxResponseTime  time.Duration
	AvgResponseTime  time.Duration
	RequestsPerSec   float64
	ResponseTimes    []time.Duration
}

func runBenchmarkLoad(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	endpoint, _ := cmd.Flags().GetString("endpoint")
	method, _ := cmd.Flags().GetString("method")
	concurrent, _ := cmd.Flags().GetInt("concurrent")
	durationStr, _ := cmd.Flags().GetString("duration")
	requestsPerSec, _ := cmd.Flags().GetInt("requests-per-sec")

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	fmt.Printf("Starting load test...\n")
	fmt.Printf("Endpoint: %s\n", endpoint)
	fmt.Printf("Method: %s\n", method)
	fmt.Printf("Concurrent users: %d\n", concurrent)
	fmt.Printf("Duration: %s\n", duration)
	if requestsPerSec > 0 {
		fmt.Printf("Target RPS: %d\n", requestsPerSec)
	}
	fmt.Println(color.YellowString("Running..."))

	// Run load test
	result := runLoadTest(c, endpoint, method, concurrent, duration, requestsPerSec)

	// Display results
	fmt.Printf("\n" + color.CyanString("Load Test Results") + "\n")
	fmt.Printf("==================\n")
	fmt.Printf("Total Requests: %d\n", result.TotalRequests)
	fmt.Printf("Successful: %d\n", result.SuccessfulReqs)
	fmt.Printf("Failed: %d\n", result.FailedRequests)
	fmt.Printf("Duration: %s\n", result.TotalDuration)
	fmt.Printf("Requests/sec: %.2f\n", result.RequestsPerSec)
	fmt.Printf("Avg Response Time: %s\n", result.AvgResponseTime)
	fmt.Printf("Min Response Time: %s\n", result.MinResponseTime)
	fmt.Printf("Max Response Time: %s\n", result.MaxResponseTime)

	errorRate := float64(result.FailedRequests) / float64(result.TotalRequests) * 100
	fmt.Printf("Error Rate: %.2f%%\n", errorRate)

	if errorRate > 5 {
		color.Red("⚠️  High error rate detected!")
	} else if result.AvgResponseTime > time.Millisecond*100 {
		color.Yellow("⚠️  High response times detected")
	} else {
		color.Green("✓ Load test completed successfully")
	}

	return nil
}

func runBenchmarkResponse(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	endpoint, _ := cmd.Flags().GetString("endpoint")
	method, _ := cmd.Flags().GetString("method")
	samples, _ := cmd.Flags().GetInt("samples")
	targetStr, _ := cmd.Flags().GetString("target")

	target, err := time.ParseDuration(targetStr)
	if err != nil {
		return fmt.Errorf("invalid target duration: %w", err)
	}

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	fmt.Printf("Testing response times...\n")
	fmt.Printf("Endpoint: %s\n", endpoint)
	fmt.Printf("Samples: %d\n", samples)
	fmt.Printf("Target: %s\n", target)

	var responseTimes []time.Duration
	var successful int
	var failed int

	for i := 0; i < samples; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		
		start := time.Now()
		resp, err := c.Request(ctx, method, endpoint, nil)
		elapsed := time.Since(start)
		
		cancel()

		if err != nil || (resp != nil && resp.StatusCode >= 400) {
			failed++
		} else {
			successful++
			responseTimes = append(responseTimes, elapsed)
		}

		if resp != nil {
			resp.Body.Close()
		}

		if i%10 == 0 {
			fmt.Printf(".")
		}
	}

	fmt.Printf("\n\n" + color.CyanString("Response Time Test Results") + "\n")
	fmt.Printf("===========================\n")
	fmt.Printf("Samples: %d\n", samples)
	fmt.Printf("Successful: %d\n", successful)
	fmt.Printf("Failed: %d\n", failed)

	if len(responseTimes) > 0 {
		// Calculate statistics
		var total time.Duration
		min := responseTimes[0]
		max := responseTimes[0]

		for _, rt := range responseTimes {
			total += rt
			if rt < min {
				min = rt
			}
			if rt > max {
				max = rt
			}
		}

		avg := total / time.Duration(len(responseTimes))

		fmt.Printf("Average: %s\n", avg)
		fmt.Printf("Minimum: %s\n", min)
		fmt.Printf("Maximum: %s\n", max)
		fmt.Printf("Target: %s\n", target)

		// Check if target is met
		if avg <= target {
			color.Green("✓ Target response time achieved!")
		} else {
			color.Red("⚠️  Target response time not met (%.2fx slower)", float64(avg)/float64(target))
		}

		// Calculate percentiles
		// Sort response times for percentile calculation
		for i := 0; i < len(responseTimes)-1; i++ {
			for j := i + 1; j < len(responseTimes); j++ {
				if responseTimes[i] > responseTimes[j] {
					responseTimes[i], responseTimes[j] = responseTimes[j], responseTimes[i]
				}
			}
		}

		p50 := responseTimes[len(responseTimes)*50/100]
		p95 := responseTimes[len(responseTimes)*95/100]
		p99 := responseTimes[len(responseTimes)*99/100]

		fmt.Printf("\nPercentiles:\n")
		fmt.Printf("50th: %s\n", p50)
		fmt.Printf("95th: %s\n", p95)
		fmt.Printf("99th: %s\n", p99)
	}

	return nil
}

func runBenchmarkMicrosecond(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	endpoint, _ := cmd.Flags().GetString("endpoint")
	samples, _ := cmd.Flags().GetInt("samples")
	validate, _ := cmd.Flags().GetBool("validate")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	fmt.Printf("Testing microsecond performance...\n")
	fmt.Printf("Endpoint: %s\n", endpoint)
	fmt.Printf("Samples: %d\n", samples)

	var responseTimes []time.Duration
	var microsecondCount int

	for i := 0; i < samples; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		
		start := time.Now()
		resp, err := c.Request(ctx, "GET", endpoint, nil)
		elapsed := time.Since(start)
		
		cancel()

		if err == nil && resp != nil && resp.StatusCode < 400 {
			responseTimes = append(responseTimes, elapsed)
			if elapsed < time.Millisecond {
				microsecondCount++
			}
		}

		if resp != nil {
			resp.Body.Close()
		}

		if i%100 == 0 {
			fmt.Printf(".")
		}
	}

	fmt.Printf("\n\n" + color.CyanString("Microsecond Performance Results") + "\n")
	fmt.Printf("================================\n")
	fmt.Printf("Total samples: %d\n", len(responseTimes))
	fmt.Printf("Sub-millisecond responses: %d\n", microsecondCount)

	if len(responseTimes) > 0 {
		var total time.Duration
		for _, rt := range responseTimes {
			total += rt
		}
		avg := total / time.Duration(len(responseTimes))

		microsecondPercentage := float64(microsecondCount) / float64(len(responseTimes)) * 100

		fmt.Printf("Average response time: %s\n", avg)
		fmt.Printf("Microsecond performance: %.2f%%\n", microsecondPercentage)

		if validate {
			if microsecondPercentage >= 90 {
				color.Green("✓ Excellent microsecond performance (%.2f%%)", microsecondPercentage)
			} else if microsecondPercentage >= 70 {
				color.Yellow("⚠️  Good microsecond performance (%.2f%%)", microsecondPercentage)
			} else {
				color.Red("⚠️  Poor microsecond performance (%.2f%%)", microsecondPercentage)
			}
		}

		// Show microsecond statistics
		if avg < time.Microsecond*1000 {
			fmt.Printf("Average in microseconds: %.2f μs\n", float64(avg.Nanoseconds())/1000)
		}
	}

	return nil
}

func runLoadTest(c *client.Client, endpoint, method string, concurrent int, duration time.Duration, requestsPerSec int) *BenchmarkResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	result := &BenchmarkResult{
		MinResponseTime: time.Hour, // Initialize to a large value
	}
	
	startTime := time.Now()
	endTime := startTime.Add(duration)
	
	// Rate limiting setup
	var rateLimiter <-chan time.Time
	if requestsPerSec > 0 {
		rateLimiter = time.Tick(time.Second / time.Duration(requestsPerSec))
	}
	
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for time.Now().Before(endTime) {
				// Rate limiting
				if rateLimiter != nil {
					<-rateLimiter
				}
				
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				
				start := time.Now()
				resp, err := c.Request(ctx, method, endpoint, nil)
				elapsed := time.Since(start)
				
				cancel()
				
				mu.Lock()
				result.TotalRequests++
				
				if err != nil || (resp != nil && resp.StatusCode >= 400) {
					result.FailedRequests++
				} else {
					result.SuccessfulReqs++
					result.ResponseTimes = append(result.ResponseTimes, elapsed)
					
					if elapsed < result.MinResponseTime {
						result.MinResponseTime = elapsed
					}
					if elapsed > result.MaxResponseTime {
						result.MaxResponseTime = elapsed
					}
				}
				mu.Unlock()
				
				if resp != nil {
					resp.Body.Close()
				}
			}
		}()
	}
	
	wg.Wait()
	
	result.TotalDuration = time.Since(startTime)
	result.RequestsPerSec = float64(result.TotalRequests) / result.TotalDuration.Seconds()
	
	// Calculate average response time
	if len(result.ResponseTimes) > 0 {
		var total time.Duration
		for _, rt := range result.ResponseTimes {
			total += rt
		}
		result.AvgResponseTime = total / time.Duration(len(result.ResponseTimes))
	}
	
	return result
}
