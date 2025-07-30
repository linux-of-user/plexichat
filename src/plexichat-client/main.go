package main

import (
	"fmt"
	"os"
	"runtime"

	"plexichat-client/cmd"
)

// Version information (set by build flags)
var (
	Version   = "1.0.0"
	Commit    = "unknown"
	BuildTime = "unknown"
	GoVersion = runtime.Version()
)

func main() {
	// Set version information for commands to use
	cmd.SetVersionInfo(Version, Commit, BuildTime, GoVersion)

	// Execute the root command
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
