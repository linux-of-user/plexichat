package cmd

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"plexichat-client/pkg/client"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authentication commands",
	Long:  "Commands for user authentication including login, logout, and registration",
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to PlexiChat",
	Long:  "Authenticate with PlexiChat server using username and password",
	RunE:  runLogin,
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from PlexiChat",
	Long:  "Clear stored authentication tokens",
	RunE:  runLogout,
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new account",
	Long:  "Create a new user account on PlexiChat server",
	RunE:  runRegister,
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current user information",
	Long:  "Display information about the currently authenticated user",
	RunE:  runWhoami,
}

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.AddCommand(loginCmd)
	authCmd.AddCommand(logoutCmd)
	authCmd.AddCommand(registerCmd)
	authCmd.AddCommand(whoamiCmd)

	// Login flags
	loginCmd.Flags().StringP("username", "u", "", "Username")
	loginCmd.Flags().StringP("password", "p", "", "Password (will prompt if not provided)")
	loginCmd.Flags().Bool("save", true, "Save authentication token")

	// Register flags
	registerCmd.Flags().StringP("username", "u", "", "Username")
	registerCmd.Flags().StringP("email", "e", "", "Email address")
	registerCmd.Flags().StringP("password", "p", "", "Password (will prompt if not provided)")
	registerCmd.Flags().String("type", "user", "Account type (user or bot)")
}

func runLogin(cmd *cobra.Command, args []string) error {
	c := client.NewClient(viper.GetString("url"))

	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	save, _ := cmd.Flags().GetBool("save")

	// Prompt for username if not provided
	if username == "" {
		fmt.Print("Username: ")
		fmt.Scanln(&username)
	}

	// Prompt for password if not provided
	if password == "" {
		fmt.Print("Password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		password = string(bytePassword)
		fmt.Println() // New line after password input
	}

	// Perform login
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	loginReq := &client.LoginRequest{
		Username: username,
		Password: password,
	}

	resp, err := c.Post(ctx, "/api/v1/auth/login", loginReq)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}

	var loginResp client.LoginResponse
	err = c.ParseResponse(resp, &loginResp)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	// Save token if requested
	if save {
		viper.Set("token", loginResp.Token)
		viper.Set("refresh_token", loginResp.RefreshToken)
		viper.Set("username", loginResp.User.Username)
		viper.Set("user_id", loginResp.User.ID)
		
		// Save to config file
		configFile := viper.ConfigFileUsed()
		if configFile == "" {
			home, _ := os.UserHomeDir()
			configFile = home + "/.plexichat-client.yaml"
		}
		
		err = viper.WriteConfigAs(configFile)
		if err != nil {
			color.Yellow("Warning: Could not save token to config file: %v", err)
		}
	}

	// Display success message
	color.Green("✓ Login successful!")
	fmt.Printf("Welcome, %s!\n", loginResp.User.Username)
	fmt.Printf("User ID: %d\n", loginResp.User.ID)
	fmt.Printf("Account Type: %s\n", loginResp.User.UserType)
	fmt.Printf("Token expires: %s\n", loginResp.ExpiresAt.Format(time.RFC3339))

	return nil
}

func runLogout(cmd *cobra.Command, args []string) error {
	// Clear stored tokens
	viper.Set("token", "")
	viper.Set("refresh_token", "")
	viper.Set("username", "")
	viper.Set("user_id", 0)

	// Save to config file
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		home, _ := os.UserHomeDir()
		configFile = home + "/.plexichat-client.yaml"
	}

	err := viper.WriteConfigAs(configFile)
	if err != nil {
		color.Yellow("Warning: Could not save config file: %v", err)
	}

	color.Green("✓ Logged out successfully!")
	return nil
}

func runRegister(cmd *cobra.Command, args []string) error {
	c := client.NewClient(viper.GetString("url"))

	username, _ := cmd.Flags().GetString("username")
	email, _ := cmd.Flags().GetString("email")
	password, _ := cmd.Flags().GetString("password")
	userType, _ := cmd.Flags().GetString("type")

	// Prompt for missing fields
	if username == "" {
		fmt.Print("Username: ")
		fmt.Scanln(&username)
	}

	if email == "" {
		fmt.Print("Email: ")
		fmt.Scanln(&email)
	}

	if password == "" {
		fmt.Print("Password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		password = string(bytePassword)
		fmt.Println()
	}

	// Perform registration
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	registerReq := &client.RegisterRequest{
		Username: username,
		Email:    email,
		Password: password,
		UserType: userType,
	}

	resp, err := c.Post(ctx, "/api/v1/auth/register", registerReq)
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}

	var user client.User
	err = c.ParseResponse(resp, &user)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	color.Green("✓ Registration successful!")
	fmt.Printf("User ID: %d\n", user.ID)
	fmt.Printf("Username: %s\n", user.Username)
	fmt.Printf("Email: %s\n", user.Email)
	fmt.Printf("Account Type: %s\n", user.UserType)
	fmt.Println("You can now login with your credentials.")

	return nil
}

func runWhoami(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.Get(ctx, "/api/v1/users/me")
	if err != nil {
		return fmt.Errorf("failed to get user info: %w", err)
	}

	var user client.User
	err = c.ParseResponse(resp, &user)
	if err != nil {
		return fmt.Errorf("failed to parse user info: %w", err)
	}

	fmt.Printf("Username: %s\n", user.Username)
	fmt.Printf("User ID: %d\n", user.ID)
	fmt.Printf("Email: %s\n", user.Email)
	fmt.Printf("Account Type: %s\n", user.UserType)
	fmt.Printf("Active: %t\n", user.IsActive)
	fmt.Printf("Admin: %t\n", user.IsAdmin)
	fmt.Printf("Created: %s\n", user.Created)

	return nil
}
