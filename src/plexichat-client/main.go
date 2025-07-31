package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"plexichat-client/cmd"
	"plexichat-client/internal/apiclient"
)

// Version information (set by build flags)
var (
	Version   = "1.0.0"
	Commit    = "unknown"
	BuildTime = "unknown"
	GoVersion = runtime.Version()

	apiClient = apiclient.NewClient("http://localhost:8080")
)

func main() {
	// Initialize API client with timeout
	apiClient.SetTimeout(5 * time.Second)

	// Configure commands with API client
	cmd.ConfigureCommands(apiClient)

	// Set version information for commands to use
	cmd.SetVersionInfo(Version, Commit, BuildTime, GoVersion)

	// Execute the root command
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
