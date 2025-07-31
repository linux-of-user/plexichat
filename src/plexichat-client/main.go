package main

import (
"fmt"
"os"
"runtime"

"plexichat-client/cmd"
)

// Version information - will be set during build
var (
version   = "dev"
commit    = "unknown"
buildTime = "unknown"
)

func main() {
// Set version information
cmd.SetVersionInfo(version, commit, buildTime, runtime.Version())

// Execute the root command
if err := cmd.Execute(); err != nil {
fmt.Fprintf(os.Stderr, "Error: %v\n", err)
os.Exit(1)
}
}
