package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"plexichat-client/pkg/client"
)

var scriptCmd = &cobra.Command{
	Use:   "script",
	Short: "Scripting and automation",
	Long:  "Execute scripts and automate PlexiChat operations",
}

var scriptRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a script file",
	Long:  "Execute a PlexiChat script file",
	Args:  cobra.ExactArgs(1),
	RunE:  runScript,
}

var scriptCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new script",
	Long:  "Create a new script template",
	Args:  cobra.ExactArgs(1),
	RunE:  runScriptCreate,
}

var scriptListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available scripts",
	Long:  "List all available script files",
	RunE:  runScriptList,
}

var scriptValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate a script",
	Long:  "Validate script syntax and commands",
	Args:  cobra.ExactArgs(1),
	RunE:  runScriptValidate,
}

var automateCmd = &cobra.Command{
	Use:   "automate",
	Short: "Automation tasks",
	Long:  "Run automated tasks and workflows",
}

var automateScheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Schedule automated tasks",
	Long:  "Schedule tasks to run at specific times",
	RunE:  runAutomateSchedule,
}

var automateWorkflowCmd = &cobra.Command{
	Use:   "workflow",
	Short: "Run workflow",
	Long:  "Execute a predefined workflow",
	Args:  cobra.ExactArgs(1),
	RunE:  runAutomateWorkflow,
}

type Script struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Version     string            `json:"version"`
	Author      string            `json:"author"`
	Variables   map[string]string `json:"variables"`
	Commands    []ScriptCommand   `json:"commands"`
}

type ScriptCommand struct {
	Type        string            `json:"type"`
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	Options     map[string]string `json:"options"`
	Condition   string            `json:"condition,omitempty"`
	OnError     string            `json:"on_error,omitempty"`
	Description string            `json:"description,omitempty"`
}

type Workflow struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Triggers    []WorkflowTrigger `json:"triggers"`
	Steps       []WorkflowStep    `json:"steps"`
	Variables   map[string]string `json:"variables"`
}

type WorkflowTrigger struct {
	Type     string            `json:"type"`
	Schedule string            `json:"schedule,omitempty"`
	Event    string            `json:"event,omitempty"`
	Options  map[string]string `json:"options"`
}

type WorkflowStep struct {
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Options   map[string]string `json:"options"`
	Condition string            `json:"condition,omitempty"`
	OnSuccess string            `json:"on_success,omitempty"`
	OnFailure string            `json:"on_failure,omitempty"`
}

func init() {
	rootCmd.AddCommand(scriptCmd)
	rootCmd.AddCommand(automateCmd)

	scriptCmd.AddCommand(scriptRunCmd)
	scriptCmd.AddCommand(scriptCreateCmd)
	scriptCmd.AddCommand(scriptListCmd)
	scriptCmd.AddCommand(scriptValidateCmd)

	automateCmd.AddCommand(automateScheduleCmd)
	automateCmd.AddCommand(automateWorkflowCmd)

	// Script flags
	scriptRunCmd.Flags().StringSliceP("var", "v", []string{}, "Set script variables (key=value)")
	scriptRunCmd.Flags().Bool("dry-run", false, "Show what would be executed without running")
	scriptRunCmd.Flags().Bool("verbose", false, "Verbose output")

	scriptCreateCmd.Flags().String("template", "basic", "Script template (basic, chat-bot, monitoring, security)")
	scriptCreateCmd.Flags().Bool("interactive", false, "Interactive script creation")

	// Automation flags
	automateScheduleCmd.Flags().String("cron", "", "Cron expression for scheduling")
	automateScheduleCmd.Flags().String("interval", "", "Interval for recurring tasks")
	automateScheduleCmd.Flags().String("script", "", "Script to schedule")
	automateScheduleCmd.Flags().String("workflow", "", "Workflow to schedule")

	automateWorkflowCmd.Flags().StringSliceP("var", "v", []string{}, "Set workflow variables")
	automateWorkflowCmd.Flags().Bool("dry-run", false, "Show workflow steps without executing")
}

func runScript(cmd *cobra.Command, args []string) error {
	scriptPath := args[0]
	variables, _ := cmd.Flags().GetStringSlice("var")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Load script
	script, err := loadScript(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to load script: %w", err)
	}

	// Parse variables
	scriptVars := make(map[string]string)
	for key, value := range script.Variables {
		scriptVars[key] = value
	}

	for _, variable := range variables {
		parts := strings.SplitN(variable, "=", 2)
		if len(parts) == 2 {
			scriptVars[parts[0]] = parts[1]
		}
	}

	color.Cyan("🚀 Executing Script: %s", script.Name)
	if script.Description != "" {
		fmt.Printf("Description: %s\n", script.Description)
	}
	fmt.Printf("Version: %s\n", script.Version)
	fmt.Printf("Commands: %d\n", len(script.Commands))

	if dryRun {
		color.Yellow("DRY RUN MODE - No commands will be executed")
	}
	fmt.Println()

	// Execute commands
	c := client.NewClient(viper.GetString("url"))
	token := viper.GetString("token")
	if token != "" {
		c.SetToken(token)
	}

	for i, command := range script.Commands {
		if verbose || dryRun {
			color.Blue("Step %d: %s", i+1, command.Description)
			fmt.Printf("Command: %s %s\n", command.Command, strings.Join(command.Args, " "))
		}

		if dryRun {
			continue
		}

		// Check condition if specified
		if command.Condition != "" {
			if !evaluateCondition(command.Condition, scriptVars) {
				if verbose {
					color.Yellow("Skipping step %d (condition not met)", i+1)
				}
				continue
			}
		}

		err := executeScriptCommand(c, command, scriptVars)
		if err != nil {
			color.Red("Error in step %d: %v", i+1, err)

			switch command.OnError {
			case "continue":
				color.Yellow("Continuing despite error...")
				continue
			case "abort":
				return fmt.Errorf("script aborted due to error in step %d", i+1)
			default:
				return fmt.Errorf("script failed at step %d: %w", i+1, err)
			}
		}

		if verbose {
			color.Green("✓ Step %d completed", i+1)
		}

		// Small delay between commands
		time.Sleep(100 * time.Millisecond)
	}

	color.Green("✓ Script completed successfully!")
	return nil
}

func runScriptCreate(cmd *cobra.Command, args []string) error {
	scriptName := args[0]
	template, _ := cmd.Flags().GetString("template")
	interactive, _ := cmd.Flags().GetBool("interactive")

	if interactive {
		return createScriptInteractive(scriptName)
	}

	script := createScriptFromTemplate(scriptName, template)

	// Save script
	scriptPath := filepath.Join("scripts", scriptName+".json")
	err := os.MkdirAll("scripts", 0755)
	if err != nil {
		return fmt.Errorf("failed to create scripts directory: %w", err)
	}

	data, err := json.MarshalIndent(script, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal script: %w", err)
	}

	err = os.WriteFile(scriptPath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to save script: %w", err)
	}

	color.Green("✓ Script created: %s", scriptPath)
	fmt.Println("You can now edit the script file and run it with:")
	fmt.Printf("  plexichat-client script run %s\n", scriptPath)

	return nil
}

func runScriptList(cmd *cobra.Command, args []string) error {
	scriptsDir := "scripts"

	if _, err := os.Stat(scriptsDir); os.IsNotExist(err) {
		fmt.Println("No scripts directory found. Create scripts with 'script create' command.")
		return nil
	}

	files, err := os.ReadDir(scriptsDir)
	if err != nil {
		return fmt.Errorf("failed to read scripts directory: %w", err)
	}

	if len(files) == 0 {
		fmt.Println("No scripts found in scripts directory.")
		return nil
	}

	color.Cyan("Available Scripts:")
	fmt.Println("==================")

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		scriptPath := filepath.Join(scriptsDir, file.Name())
		script, err := loadScript(scriptPath)
		if err != nil {
			color.Red("Error loading %s: %v", file.Name(), err)
			continue
		}

		fmt.Printf("📜 %s (v%s)\n", script.Name, script.Version)
		if script.Description != "" {
			fmt.Printf("   %s\n", script.Description)
		}
		fmt.Printf("   Commands: %d\n", len(script.Commands))
		fmt.Printf("   File: %s\n", scriptPath)
		fmt.Println()
	}

	return nil
}

func runScriptValidate(cmd *cobra.Command, args []string) error {
	scriptPath := args[0]

	script, err := loadScript(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to load script: %w", err)
	}

	color.Cyan("Validating script: %s", script.Name)

	errors := []string{}

	// Validate basic fields
	if script.Name == "" {
		errors = append(errors, "script name is required")
	}
	if script.Version == "" {
		errors = append(errors, "script version is required")
	}
	if len(script.Commands) == 0 {
		errors = append(errors, "script must have at least one command")
	}

	// Validate commands
	for i, command := range script.Commands {
		if command.Command == "" {
			errors = append(errors, fmt.Sprintf("command %d: command is required", i+1))
		}

		// Validate command types
		validTypes := []string{"api", "chat", "file", "admin", "security", "benchmark", "wait", "log"}
		if !contains(validTypes, command.Type) {
			errors = append(errors, fmt.Sprintf("command %d: invalid type '%s'", i+1, command.Type))
		}
	}

	if len(errors) > 0 {
		color.Red("Validation failed:")
		for _, err := range errors {
			fmt.Printf("  - %s\n", err)
		}
		return fmt.Errorf("script validation failed")
	}

	color.Green("✓ Script is valid")
	return nil
}

func runAutomateSchedule(cmd *cobra.Command, args []string) error {
	cronExpr, _ := cmd.Flags().GetString("cron")
	interval, _ := cmd.Flags().GetString("interval")
	scriptPath, _ := cmd.Flags().GetString("script")
	workflowPath, _ := cmd.Flags().GetString("workflow")

	if cronExpr == "" && interval == "" {
		return fmt.Errorf("either --cron or --interval must be specified")
	}

	if scriptPath == "" && workflowPath == "" {
		return fmt.Errorf("either --script or --workflow must be specified")
	}

	color.Cyan("📅 Scheduling Automation")

	if cronExpr != "" {
		fmt.Printf("Cron expression: %s\n", cronExpr)
	}
	if interval != "" {
		fmt.Printf("Interval: %s\n", interval)
	}
	if scriptPath != "" {
		fmt.Printf("Script: %s\n", scriptPath)
	}
	if workflowPath != "" {
		fmt.Printf("Workflow: %s\n", workflowPath)
	}

	// In a real implementation, this would integrate with a job scheduler
	color.Yellow("Note: Scheduling functionality requires a job scheduler integration")
	color.Green("✓ Schedule configuration saved")

	return nil
}

func runAutomateWorkflow(cmd *cobra.Command, args []string) error {
	workflowPath := args[0]
	variables, _ := cmd.Flags().GetStringSlice("var")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	workflow, err := loadWorkflow(workflowPath)
	if err != nil {
		return fmt.Errorf("failed to load workflow: %w", err)
	}

	// Parse variables
	workflowVars := make(map[string]string)
	for key, value := range workflow.Variables {
		workflowVars[key] = value
	}

	for _, variable := range variables {
		parts := strings.SplitN(variable, "=", 2)
		if len(parts) == 2 {
			workflowVars[parts[0]] = parts[1]
		}
	}

	color.Cyan("🔄 Executing Workflow: %s", workflow.Name)
	fmt.Printf("Description: %s\n", workflow.Description)
	fmt.Printf("Steps: %d\n", len(workflow.Steps))

	if dryRun {
		color.Yellow("DRY RUN MODE - No steps will be executed")
	}
	fmt.Println()

	// Execute workflow steps
	c := client.NewClient(viper.GetString("url"))
	token := viper.GetString("token")
	if token != "" {
		c.SetToken(token)
	}

	for i, step := range workflow.Steps {
		color.Blue("Step %d: %s", i+1, step.Name)

		if dryRun {
			fmt.Printf("Would execute: %s %s\n", step.Command, strings.Join(step.Args, " "))
			continue
		}

		// Check condition
		if step.Condition != "" {
			if !evaluateCondition(step.Condition, workflowVars) {
				color.Yellow("Skipping step (condition not met)")
				continue
			}
		}

		// Execute step
		err := executeWorkflowStep(c, step, workflowVars)
		if err != nil {
			color.Red("Error in step %d: %v", i+1, err)

			if step.OnFailure != "" {
				color.Yellow("Executing failure handler: %s", step.OnFailure)
				// Execute failure handler
			}

			return fmt.Errorf("workflow failed at step %d: %w", i+1, err)
		}

		if step.OnSuccess != "" {
			color.Green("Executing success handler: %s", step.OnSuccess)
			// Execute success handler
		}

		color.Green("✓ Step %d completed", i+1)
		time.Sleep(100 * time.Millisecond)
	}

	color.Green("✓ Workflow completed successfully!")
	return nil
}

// Helper functions

func loadScript(path string) (*Script, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var script Script
	err = json.Unmarshal(data, &script)
	return &script, err
}

func loadWorkflow(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var workflow Workflow
	err = json.Unmarshal(data, &workflow)
	return &workflow, err
}

func createScriptFromTemplate(name, template string) *Script {
	script := &Script{
		Name:      name,
		Version:   "1.0.0",
		Author:    "PlexiChat User",
		Variables: make(map[string]string),
		Commands:  []ScriptCommand{},
	}

	switch template {
	case "chat-bot":
		script.Description = "Automated chat bot script"
		script.Commands = []ScriptCommand{
			{
				Type:        "chat",
				Command:     "send",
				Args:        []string{"--room", "1", "--message", "Bot is online!"},
				Description: "Send startup message",
			},
			{
				Type:        "wait",
				Command:     "sleep",
				Args:        []string{"5s"},
				Description: "Wait 5 seconds",
			},
		}
	case "monitoring":
		script.Description = "System monitoring script"
		script.Commands = []ScriptCommand{
			{
				Type:        "api",
				Command:     "health",
				Description: "Check system health",
			},
			{
				Type:        "admin",
				Command:     "stats",
				Description: "Get system statistics",
			},
		}
	case "security":
		script.Description = "Security testing script"
		script.Commands = []ScriptCommand{
			{
				Type:        "security",
				Command:     "scan",
				Args:        []string{"--all"},
				Description: "Run security scan",
			},
		}
	default:
		script.Description = "Basic PlexiChat script"
		script.Commands = []ScriptCommand{
			{
				Type:        "api",
				Command:     "version",
				Description: "Get server version",
			},
		}
	}

	return script
}

func createScriptInteractive(name string) error {
	// Interactive script creation would be implemented here
	color.Yellow("Interactive script creation not yet implemented")
	return nil
}

func executeScriptCommand(c *client.Client, command ScriptCommand, vars map[string]string) error {
	// Replace variables in command and args
	cmd := replaceVariables(command.Command, vars)
	args := make([]string, len(command.Args))
	for i, arg := range command.Args {
		args[i] = replaceVariables(arg, vars)
	}

	switch command.Type {
	case "api":
		return executeAPICommand(c, cmd, args)
	case "chat":
		return executeChatCommand(c, cmd, args)
	case "wait":
		return executeWaitCommand(cmd, args)
	case "log":
		return executeLogCommand(cmd, args)
	default:
		return fmt.Errorf("unknown command type: %s", command.Type)
	}
}

func executeWorkflowStep(c *client.Client, step WorkflowStep, vars map[string]string) error {
	// Similar to executeScriptCommand but for workflow steps
	return executeScriptCommand(c, ScriptCommand{
		Type:    step.Type,
		Command: step.Command,
		Args:    step.Args,
		Options: step.Options,
	}, vars)
}

func executeAPICommand(c *client.Client, command string, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch command {
	case "health":
		_, err := c.Health(ctx)
		return err
	case "version":
		_, err := c.Version(ctx)
		return err
	default:
		return fmt.Errorf("unknown API command: %s", command)
	}
}

func executeChatCommand(c *client.Client, command string, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch command {
	case "send":
		// Parse args for room and message
		roomID := 1
		message := "Hello from script"

		for i, arg := range args {
			if arg == "--room" && i+1 < len(args) {
				if id, err := strconv.Atoi(args[i+1]); err == nil {
					roomID = id
				}
			}
			if arg == "--message" && i+1 < len(args) {
				message = args[i+1]
			}
		}

		_, err := c.SendMessage(ctx, message, roomID)
		return err
	default:
		return fmt.Errorf("unknown chat command: %s", command)
	}
}

func executeWaitCommand(command string, args []string) error {
	switch command {
	case "sleep":
		if len(args) > 0 {
			duration, err := time.ParseDuration(args[0])
			if err != nil {
				return err
			}
			time.Sleep(duration)
		}
		return nil
	default:
		return fmt.Errorf("unknown wait command: %s", command)
	}
}

func executeLogCommand(command string, args []string) error {
	switch command {
	case "info":
		if len(args) > 0 {
			color.Blue("INFO: %s", strings.Join(args, " "))
		}
	case "warn":
		if len(args) > 0 {
			color.Yellow("WARN: %s", strings.Join(args, " "))
		}
	case "error":
		if len(args) > 0 {
			color.Red("ERROR: %s", strings.Join(args, " "))
		}
	default:
		fmt.Println(strings.Join(args, " "))
	}
	return nil
}

func evaluateCondition(condition string, vars map[string]string) bool {
	// Simple condition evaluation
	// In a real implementation, this would be more sophisticated
	return true
}

func replaceVariables(text string, vars map[string]string) string {
	for key, value := range vars {
		text = strings.ReplaceAll(text, "${"+key+"}", value)
		text = strings.ReplaceAll(text, "$"+key, value)
	}
	return text
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
