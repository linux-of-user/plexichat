package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/gorilla/websocket"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"plexichat-client/pkg/client"
)

var chatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Chat commands",
	Long:  "Commands for sending messages, listening to chat, and managing rooms",
}

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a message",
	Long:  "Send a message to a chat room",
	RunE:  runSend,
}

var listenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Listen to chat messages",
	Long:  "Listen to real-time chat messages via WebSocket",
	RunE:  runListen,
}

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Get chat history",
	Long:  "Retrieve chat message history for a room",
	RunE:  runHistory,
}

var roomsCmd = &cobra.Command{
	Use:   "rooms",
	Short: "List chat rooms",
	Long:  "List available chat rooms",
	RunE:  runRooms,
}

func init() {
	rootCmd.AddCommand(chatCmd)
	chatCmd.AddCommand(sendCmd)
	chatCmd.AddCommand(listenCmd)
	chatCmd.AddCommand(historyCmd)
	chatCmd.AddCommand(roomsCmd)

	// Send flags
	sendCmd.Flags().StringP("message", "m", "", "Message content")
	sendCmd.Flags().IntP("room", "r", 1, "Room ID")
	sendCmd.MarkFlagRequired("message")

	// Listen flags
	listenCmd.Flags().IntP("room", "r", 1, "Room ID to listen to")
	listenCmd.Flags().Bool("all", false, "Listen to all rooms")

	// History flags
	historyCmd.Flags().IntP("room", "r", 1, "Room ID")
	historyCmd.Flags().IntP("limit", "l", 50, "Number of messages to retrieve")
	historyCmd.Flags().IntP("page", "p", 1, "Page number")
}

func runSend(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	message, _ := cmd.Flags().GetString("message")
	roomID, _ := cmd.Flags().GetInt("room")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sendReq := &client.SendMessageRequest{
		Content: message,
		RoomID:  roomID,
	}

	resp, err := c.Post(ctx, "/api/v1/messages", sendReq)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	var msg client.Message
	err = c.ParseResponse(resp, &msg)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	color.Green("✓ Message sent successfully!")
	fmt.Printf("Message ID: %d\n", msg.ID)
	fmt.Printf("Room: %s (ID: %d)\n", msg.RoomName, msg.RoomID)
	fmt.Printf("Timestamp: %s\n", msg.Timestamp.Format(time.RFC3339))

	return nil
}

func runListen(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	roomID, _ := cmd.Flags().GetInt("room")
	listenAll, _ := cmd.Flags().GetBool("all")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	// Determine WebSocket endpoint
	endpoint := "/ws/chat"
	if !listenAll {
		endpoint = fmt.Sprintf("/ws/chat/room/%d", roomID)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to WebSocket
	conn, err := c.ConnectWebSocket(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}
	defer conn.Close()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	color.Green("✓ Connected to chat!")
	if listenAll {
		fmt.Println("Listening to all rooms... (Press Ctrl+C to exit)")
	} else {
		fmt.Printf("Listening to room %d... (Press Ctrl+C to exit)\n", roomID)
	}
	fmt.Println(strings.Repeat("-", 50))

	// Listen for messages
	go func() {
		for {
			var wsMsg client.WebSocketMessage
			err := conn.ReadJSON(&wsMsg)
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					color.Red("WebSocket error: %v", err)
				}
				cancel()
				return
			}

			// Handle different message types
			switch wsMsg.Type {
			case "message":
				// Parse message data
				msgData, _ := json.Marshal(wsMsg.Data)
				var msg client.Message
				json.Unmarshal(msgData, &msg)

				// Display message
				timestamp := msg.Timestamp.Format("15:04:05")
				roomInfo := ""
				if listenAll {
					roomInfo = fmt.Sprintf("[%s] ", msg.RoomName)
				}
				
				color.Cyan("[%s] %s%s: %s", timestamp, roomInfo, msg.Username, msg.Content)

			case "user_joined":
				color.Yellow("→ User joined the room")
			case "user_left":
				color.Yellow("← User left the room")
			case "typing":
				color.Blue("💬 Someone is typing...")
			default:
				if viper.GetBool("verbose") {
					fmt.Printf("Unknown message type: %s\n", wsMsg.Type)
				}
			}
		}
	}()

	// Wait for signal or context cancellation
	select {
	case <-sigChan:
		fmt.Println("\nDisconnecting...")
	case <-ctx.Done():
		fmt.Println("\nConnection closed")
	}

	return nil
}

func runHistory(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	roomID, _ := cmd.Flags().GetInt("room")
	limit, _ := cmd.Flags().GetInt("limit")
	page, _ := cmd.Flags().GetInt("page")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	endpoint := fmt.Sprintf("/api/v1/messages?room_id=%d&limit=%d&page=%d", roomID, limit, page)
	resp, err := c.Get(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to get message history: %w", err)
	}

	var listResp client.ListResponse
	err = c.ParseResponse(resp, &listResp)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Parse messages
	messagesData, _ := json.Marshal(listResp.Items)
	var messages []client.Message
	json.Unmarshal(messagesData, &messages)

	if len(messages) == 0 {
		fmt.Println("No messages found.")
		return nil
	}

	// Display messages in a table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Username", "Message", "Timestamp"})
	table.SetBorder(false)
	table.SetRowSeparator("-")
	table.SetColumnSeparator("|")
	table.SetCenterSeparator("+")

	for _, msg := range messages {
		content := msg.Content
		if len(content) > 50 {
			content = content[:47] + "..."
		}
		
		table.Append([]string{
			strconv.Itoa(msg.ID),
			msg.Username,
			content,
			msg.Timestamp.Format("2006-01-02 15:04:05"),
		})
	}

	fmt.Printf("Message History - Room %d (Page %d of %d)\n", roomID, page, listResp.TotalPages)
	table.Render()
	fmt.Printf("Total messages: %d\n", listResp.Total)

	return nil
}

func runRooms(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.Get(ctx, "/api/v1/rooms")
	if err != nil {
		return fmt.Errorf("failed to get rooms: %w", err)
	}

	var listResp client.ListResponse
	err = c.ParseResponse(resp, &listResp)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Parse rooms
	roomsData, _ := json.Marshal(listResp.Items)
	var rooms []client.Room
	json.Unmarshal(roomsData, &rooms)

	if len(rooms) == 0 {
		fmt.Println("No rooms found.")
		return nil
	}

	// Display rooms in a table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Name", "Description", "Private", "Created"})
	table.SetBorder(false)
	table.SetRowSeparator("-")
	table.SetColumnSeparator("|")
	table.SetCenterSeparator("+")

	for _, room := range rooms {
		description := room.Description
		if len(description) > 40 {
			description = description[:37] + "..."
		}
		
		private := "No"
		if room.IsPrivate {
			private = "Yes"
		}
		
		table.Append([]string{
			strconv.Itoa(room.ID),
			room.Name,
			description,
			private,
			room.Created,
		})
	}

	fmt.Println("Available Chat Rooms:")
	table.Render()
	fmt.Printf("Total rooms: %d\n", listResp.Total)

	return nil
}
