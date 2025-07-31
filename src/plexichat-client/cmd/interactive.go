package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"plexichat-client/pkg/client"
)

var interactiveCmd = &cobra.Command{
	Use:   "interactive",
	Short: "Interactive mode",
	Long:  "Start interactive mode for easier PlexiChat interaction",
	Aliases: []string{"i", "shell"},
	RunE:  runInteractive,
}

func init() {
	rootCmd.AddCommand(interactiveCmd)
}

func runInteractive(cmd *cobra.Command, args []string) error {
	color.Cyan("🚀 Welcome to PlexiChat Interactive Mode!")
	fmt.Println("Type 'help' for available commands or 'exit' to quit.")
	fmt.Println()

	c := client.NewClient(viper.GetString("url"))
	
	// Check if already logged in
	token := viper.GetString("token")
	if token != "" {
		c.SetToken(token)
		username := viper.GetString("username")
		if username != "" {
			color.Green("✓ Already logged in as: %s", username)
		}
	} else {
		color.Yellow("⚠️  Not logged in. Use 'login' command to authenticate.")
	}
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	
	for {
		fmt.Print(color.BlueString("plexichat> "))
		
		if !scanner.Scan() {
			break
		}
		
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}
		
		parts := strings.Fields(input)
		command := parts[0]
		args := parts[1:]
		
		switch command {
		case "help", "h":
			showInteractiveHelp()
		case "exit", "quit", "q":
			color.Green("👋 Goodbye!")
			return nil
		case "login", "l":
			err := interactiveLogin(c)
			if err != nil {
				color.Red("Login failed: %v", err)
			}
		case "whoami", "me":
			err := interactiveWhoami(c)
			if err != nil {
				color.Red("Error: %v", err)
			}
		case "rooms", "r":
			err := interactiveRooms(c)
			if err != nil {
				color.Red("Error: %v", err)
			}
		case "chat", "c":
			if len(args) > 0 {
				roomID, err := strconv.Atoi(args[0])
				if err != nil {
					color.Red("Invalid room ID: %s", args[0])
					continue
				}
				err = interactiveChat(c, roomID)
				if err != nil {
					color.Red("Chat error: %v", err)
				}
			} else {
				color.Yellow("Usage: chat <room_id>")
			}
		case "send", "s":
			if len(args) >= 2 {
				roomID, err := strconv.Atoi(args[0])
				if err != nil {
					color.Red("Invalid room ID: %s", args[0])
					continue
				}
				message := strings.Join(args[1:], " ")
				err = interactiveSend(c, roomID, message)
				if err != nil {
					color.Red("Send error: %v", err)
				}
			} else {
				color.Yellow("Usage: send <room_id> <message>")
			}
		case "files", "f":
			err := interactiveFiles(c)
			if err != nil {
				color.Red("Error: %v", err)
			}
		case "upload", "u":
			if len(args) > 0 {
				err := interactiveUpload(c, args[0])
				if err != nil {
					color.Red("Upload error: %v", err)
				}
			} else {
				color.Yellow("Usage: upload <file_path>")
			}
		case "health":
			err := interactiveHealth(c)
			if err != nil {
				color.Red("Error: %v", err)
			}
		case "version", "v":
			err := interactiveVersion(c)
			if err != nil {
				color.Red("Error: %v", err)
			}
		case "clear", "cls":
			fmt.Print("\033[2J\033[H") // Clear screen
		case "status":
			showStatus(c)
		default:
			color.Red("Unknown command: %s", command)
			color.Yellow("Type 'help' for available commands")
		}
		
		fmt.Println()
	}
	
	return nil
}

func showInteractiveHelp() {
	color.Cyan("Available Commands:")
	fmt.Println("  help, h          - Show this help")
	fmt.Println("  login, l         - Login to PlexiChat")
	fmt.Println("  whoami, me       - Show current user info")
	fmt.Println("  rooms, r         - List chat rooms")
	fmt.Println("  chat <room_id>   - Enter chat mode for a room")
	fmt.Println("  send <room> <msg>- Send a message")
	fmt.Println("  files, f         - List files")
	fmt.Println("  upload <path>    - Upload a file")
	fmt.Println("  health           - Check server health")
	fmt.Println("  version, v       - Show version info")
	fmt.Println("  status           - Show connection status")
	fmt.Println("  clear, cls       - Clear screen")
	fmt.Println("  exit, quit, q    - Exit interactive mode")
}

func interactiveLogin(c *client.Client) error {
	prompt := promptui.Prompt{
		Label: "Username",
	}
	username, err := prompt.Run()
	if err != nil {
		return err
	}

	prompt = promptui.Prompt{
		Label: "Password",
		Mask:  '*',
	}
	password, err := prompt.Run()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	loginResp, err := c.Login(ctx, username, password)
	if err != nil {
		return err
	}

	// Save credentials
	viper.Set("token", loginResp.Token)
	viper.Set("refresh_token", loginResp.RefreshToken)
	viper.Set("username", loginResp.User.Username)
	viper.Set("user_id", loginResp.User.ID)

	color.Green("✓ Login successful! Welcome, %s", loginResp.User.Username)
	return nil
}

func interactiveWhoami(c *client.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	user, err := c.GetCurrentUser(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("Username: %s\n", user.Username)
	fmt.Printf("User ID: %d\n", user.ID)
	fmt.Printf("Email: %s\n", user.Email)
	fmt.Printf("Account Type: %s\n", user.UserType)
	fmt.Printf("Active: %t\n", user.IsActive)
	fmt.Printf("Admin: %t\n", user.IsAdmin)

	return nil
}

func interactiveRooms(c *client.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rooms, err := c.GetRooms(ctx, 20, 1)
	if err != nil {
		return err
	}

	if len(rooms.Rooms) == 0 {
		fmt.Println("No rooms available.")
		return nil
	}

	color.Cyan("Available Rooms:")
	for _, room := range rooms.Rooms {
		private := ""
		if room.IsPrivate {
			private = " (Private)"
		}
		fmt.Printf("  %d: %s%s - %s\n", room.ID, room.Name, private, room.Description)
	}

	return nil
}

func interactiveChat(c *client.Client, roomID int) error {
	color.Green("Entering chat mode for room %d (type '/exit' to leave)", roomID)
	
	scanner := bufio.NewScanner(os.Stdin)
	
	for {
		fmt.Print(color.YellowString("chat> "))
		
		if !scanner.Scan() {
			break
		}
		
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}
		
		if input == "/exit" || input == "/quit" {
			color.Green("Leaving chat mode")
			break
		}
		
		if input == "/history" {
			err := showChatHistory(c, roomID)
			if err != nil {
				color.Red("Error getting history: %v", err)
			}
			continue
		}
		
		// Send message
		err := interactiveSend(c, roomID, input)
		if err != nil {
			color.Red("Send error: %v", err)
		}
	}
	
	return nil
}

func interactiveSend(c *client.Client, roomID int, message string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	msg, err := c.SendMessage(ctx, message, roomID)
	if err != nil {
		return err
	}

	color.Green("✓ Message sent (ID: %d)", msg.ID)
	return nil
}

func interactiveFiles(c *client.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	files, err := c.GetFiles(ctx, 20, 1, "")
	if err != nil {
		return err
	}

	if len(files.Files) == 0 {
		fmt.Println("No files found.")
		return nil
	}

	color.Cyan("Your Files:")
	for _, file := range files.Files {
		size := fmt.Sprintf("%.2f MB", float64(file.Size)/1024/1024)
		if file.Size < 1024*1024 {
			size = fmt.Sprintf("%.2f KB", float64(file.Size)/1024)
		}
		fmt.Printf("  %d: %s (%s) - %s\n", file.ID, file.Filename, size, file.Uploaded)
	}

	return nil
}

func interactiveUpload(c *client.Client, filePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	fmt.Printf("Uploading %s...\n", filePath)
	
	resp, err := c.UploadFile(ctx, "/api/v1/files", filePath)
	if err != nil {
		return err
	}

	var file client.File
	err = c.ParseResponse(resp, &file)
	if err != nil {
		return err
	}

	color.Green("✓ File uploaded successfully!")
	fmt.Printf("File ID: %d\n", file.ID)
	fmt.Printf("URL: %s\n", file.URL)

	return nil
}

func interactiveHealth(c *client.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	health, err := c.Health(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("Status: %s\n", health.Status)
	fmt.Printf("Version: %s\n", health.Version)
	fmt.Printf("Uptime: %s\n", health.Uptime)

	return nil
}

func interactiveVersion(c *client.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	version, err := c.Version(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("Server Version: %s\n", version.Version)
	fmt.Printf("API Version: %s\n", version.APIVersion)
	fmt.Printf("Build: %d\n", version.BuildNumber)

	return nil
}

func showStatus(c *client.Client) {
	fmt.Printf("Server URL: %s\n", viper.GetString("url"))
	
	token := viper.GetString("token")
	if token != "" {
		username := viper.GetString("username")
		color.Green("✓ Authenticated as: %s", username)
	} else {
		color.Red("✗ Not authenticated")
	}
}

func showChatHistory(c *client.Client, roomID int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	messages, err := c.GetMessages(ctx, roomID, 10, 1)
	if err != nil {
		return err
	}

	if len(messages.Messages) == 0 {
		fmt.Println("No message history.")
		return nil
	}

	color.Cyan("Recent Messages:")
	for _, msg := range messages.Messages {
		timestamp := msg.Timestamp.Format("15:04:05")
		fmt.Printf("[%s] %s: %s\n", timestamp, msg.Username, msg.Content)
	}

	return nil
}
