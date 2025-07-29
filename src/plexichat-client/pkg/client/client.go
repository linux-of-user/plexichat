package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Client represents the PlexiChat API client
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	APIKey     string
	Token      string
	UserAgent  string
}

// NewClient creates a new PlexiChat API client
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		UserAgent: "PlexiChat-Go-Client/1.0",
	}
}

// SetAPIKey sets the API key for authentication
func (c *Client) SetAPIKey(apiKey string) {
	c.APIKey = apiKey
}

// SetToken sets the JWT token for authentication
func (c *Client) SetToken(token string) {
	c.Token = token
}

// Request makes an HTTP request to the PlexiChat API
func (c *Client) Request(ctx context.Context, method, endpoint string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	url := c.BaseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	// Set authentication
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	} else if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}

	return c.HTTPClient.Do(req)
}

// Get makes a GET request
func (c *Client) Get(ctx context.Context, endpoint string) (*http.Response, error) {
	return c.Request(ctx, "GET", endpoint, nil)
}

// Post makes a POST request
func (c *Client) Post(ctx context.Context, endpoint string, body interface{}) (*http.Response, error) {
	return c.Request(ctx, "POST", endpoint, body)
}

// Put makes a PUT request
func (c *Client) Put(ctx context.Context, endpoint string, body interface{}) (*http.Response, error) {
	return c.Request(ctx, "PUT", endpoint, body)
}

// Delete makes a DELETE request
func (c *Client) Delete(ctx context.Context, endpoint string) (*http.Response, error) {
	return c.Request(ctx, "DELETE", endpoint, nil)
}

// UploadFile uploads a file to the specified endpoint
func (c *Client) UploadFile(ctx context.Context, endpoint, filePath string) (*http.Response, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Create form file field
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	// Copy file content
	_, err = io.Copy(part, file)
	if err != nil {
		return nil, fmt.Errorf("failed to copy file content: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close writer: %w", err)
	}

	// Create request
	url := c.BaseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, "POST", url, &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", c.UserAgent)

	// Set authentication
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	} else if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}

	return c.HTTPClient.Do(req)
}

// ConnectWebSocket establishes a WebSocket connection
func (c *Client) ConnectWebSocket(ctx context.Context, endpoint string) (*websocket.Conn, error) {
	// Convert HTTP URL to WebSocket URL
	wsURL := strings.Replace(c.BaseURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL += endpoint

	// Parse URL and add authentication if needed
	u, err := url.Parse(wsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse WebSocket URL: %w", err)
	}

	// Set up headers
	headers := http.Header{}
	headers.Set("User-Agent", c.UserAgent)
	
	if c.Token != "" {
		headers.Set("Authorization", "Bearer "+c.Token)
	} else if c.APIKey != "" {
		headers.Set("X-API-Key", c.APIKey)
	}

	// Create WebSocket connection
	dialer := websocket.DefaultDialer
	conn, _, err := dialer.DialContext(ctx, u.String(), headers)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	return conn, nil
}

// ParseResponse parses an HTTP response into a struct
func (c *Client) ParseResponse(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	if v != nil {
		err = json.Unmarshal(body, v)
		if err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// Health checks the health of the PlexiChat server
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	resp, err := c.Get(ctx, "/health")
	if err != nil {
		return nil, err
	}

	var health HealthResponse
	err = c.ParseResponse(resp, &health)
	return &health, err
}

// Version gets the version information
func (c *Client) Version(ctx context.Context) (*VersionResponse, error) {
	resp, err := c.Get(ctx, "/api/v1/version")
	if err != nil {
		return nil, err
	}

	var version VersionResponse
	err = c.ParseResponse(resp, &version)
	return &version, err
}

// Login authenticates with username and password
func (c *Client) Login(ctx context.Context, username, password string) (*LoginResponse, error) {
	loginReq := &LoginRequest{
		Username: username,
		Password: password,
	}

	resp, err := c.Post(ctx, "/api/v1/auth/login", loginReq)
	if err != nil {
		return nil, err
	}

	var loginResp LoginResponse
	err = c.ParseResponse(resp, &loginResp)
	if err != nil {
		return nil, err
	}

	// Set token for future requests
	c.SetToken(loginResp.Token)
	return &loginResp, nil
}

// Register creates a new user account
func (c *Client) Register(ctx context.Context, username, email, password, userType string) (*User, error) {
	registerReq := &RegisterRequest{
		Username: username,
		Email:    email,
		Password: password,
		UserType: userType,
	}

	resp, err := c.Post(ctx, "/api/v1/auth/register", registerReq)
	if err != nil {
		return nil, err
	}

	var user User
	err = c.ParseResponse(resp, &user)
	return &user, err
}

// GetCurrentUser gets information about the current user
func (c *Client) GetCurrentUser(ctx context.Context) (*User, error) {
	resp, err := c.Get(ctx, "/api/v1/users/me")
	if err != nil {
		return nil, err
	}

	var user User
	err = c.ParseResponse(resp, &user)
	return &user, err
}

// SendMessage sends a message to a chat room
func (c *Client) SendMessage(ctx context.Context, content string, roomID int) (*Message, error) {
	sendReq := &SendMessageRequest{
		Content: content,
		RoomID:  roomID,
	}

	resp, err := c.Post(ctx, "/api/v1/messages", sendReq)
	if err != nil {
		return nil, err
	}

	var message Message
	err = c.ParseResponse(resp, &message)
	return &message, err
}

// GetMessages retrieves messages with pagination
func (c *Client) GetMessages(ctx context.Context, roomID, limit, page int) (*MessageListResponse, error) {
	endpoint := fmt.Sprintf("/api/v1/messages?room_id=%d&limit=%d&page=%d", roomID, limit, page)
	resp, err := c.Get(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var listResp MessageListResponse
	err = c.ParseResponse(resp, &listResp)
	return &listResp, err
}

// GetRooms retrieves available chat rooms
func (c *Client) GetRooms(ctx context.Context, limit, page int) (*RoomListResponse, error) {
	endpoint := fmt.Sprintf("/api/v1/rooms?limit=%d&page=%d", limit, page)
	resp, err := c.Get(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var listResp RoomListResponse
	err = c.ParseResponse(resp, &listResp)
	return &listResp, err
}

// GetFiles retrieves uploaded files
func (c *Client) GetFiles(ctx context.Context, limit, page int, fileType string) (*FileListResponse, error) {
	endpoint := fmt.Sprintf("/api/v1/files?limit=%d&page=%d", limit, page)
	if fileType != "" {
		endpoint += "&type=" + fileType
	}

	resp, err := c.Get(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var listResp FileListResponse
	err = c.ParseResponse(resp, &listResp)
	return &listResp, err
}

// GetFileInfo gets information about a specific file
func (c *Client) GetFileInfo(ctx context.Context, fileID int) (*File, error) {
	resp, err := c.Get(ctx, fmt.Sprintf("/api/v1/files/%d", fileID))
	if err != nil {
		return nil, err
	}

	var file File
	err = c.ParseResponse(resp, &file)
	return &file, err
}

// DeleteFile deletes a file
func (c *Client) DeleteFile(ctx context.Context, fileID int) error {
	resp, err := c.Delete(ctx, fmt.Sprintf("/api/v1/files/%d", fileID))
	if err != nil {
		return err
	}

	return c.ParseResponse(resp, nil)
}
