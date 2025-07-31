package client

import "time"

// --- 2FA/MFA Types ---

// 2FA method types
const (
	TwoFAMethodTOTP       = "totp"
	TwoFAMethodSMS        = "sms"
	TwoFAMethodEmail      = "email"
	TwoFAMethodBackupCode = "backup_code"
	TwoFAMethodHardware   = "hardware"
)

// 2FA Setup Request
// Used to initiate 2FA setup for a method (TOTP, SMS, Email, Hardware)
type TwoFASetupRequest struct {
	Method string `json:"method"` // "totp", "sms", "email", "hardware"
	Destination string `json:"destination,omitempty"` // For SMS/email: phone/email
}

// 2FA Setup Response
// Backend returns details needed for setup (e.g., QR code for TOTP, challenge for hardware, etc.)
type TwoFASetupResponse struct {
	Method string `json:"method"`
	Secret string `json:"secret,omitempty"`
	QRCode string `json:"qrcode,omitempty"`
	Challenge string `json:"challenge,omitempty"`
	BackupCodes []string `json:"backup_codes,omitempty"`
	Message string `json:"message,omitempty"`
}

// 2FA Verify Setup Request
// Used to verify the setup of a 2FA method (e.g., enter TOTP code, respond to hardware challenge)
type TwoFAVerifySetupRequest struct {
	Method string `json:"method"`
	Code   string `json:"code"`
	ChallengeResponse string `json:"challenge_response,omitempty"`
}

// 2FA Verify Setup Response
type TwoFAVerifySetupResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	BackupCodes []string `json:"backup_codes,omitempty"`
}

// 2FA Login Request
// Used when a user must provide a 2FA code after username/password
type TwoFALoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Method   string `json:"method"`
	Code     string `json:"code"`
	ChallengeResponse string `json:"challenge_response,omitempty"`
}

// 2FA Login Response (same as LoginResponse, but may include 2FA-required flag)
type TwoFALoginResponse struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	User         User      `json:"user"`
	TwoFARequired bool     `json:"two_fa_required"`
	Methods      []string  `json:"methods,omitempty"`
	Message      string    `json:"message,omitempty"`
}

// 2FA Status Response
type TwoFAStatusResponse struct {
	Enabled  bool     `json:"enabled"`
	Methods  []string `json:"methods"`
	Primary  string   `json:"primary"`
	BackupCodes []string `json:"backup_codes,omitempty"`
}

// 2FA Backup Codes Response
type TwoFABackupCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

// 2FA Disable Request
type TwoFADisableRequest struct {
	Method string `json:"method"`
	Code   string `json:"code,omitempty"`
}

// 2FA Disable Response
type TwoFADisableResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// --- End 2FA/MFA Types ---


// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp string            `json:"timestamp"`
	Version   string            `json:"version"`
	Uptime    string            `json:"uptime"`
	Checks    map[string]string `json:"checks"`
}

// VersionResponse represents the version information response
type VersionResponse struct {
	Version     string `json:"version"`
	APIVersion  string `json:"api_version"`
	BuildNumber int    `json:"build_number"`
	ReleaseDate string `json:"release_date"`
	Status      string `json:"status"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents a login response. It may or may not include a token.
// If TwoFARequired is true, the client must perform a second step using the /login-2fa endpoint.
type LoginResponse struct {
	Token         string    `json:"token,omitempty"`
	RefreshToken  string    `json:"refresh_token,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	User          *User     `json:"user,omitempty"`
	TwoFARequired bool      `json:"two_fa_required"`
	Methods       []string  `json:"methods,omitempty"` // Available 2FA methods if required
	Message       string    `json:"message,omitempty"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	UserType string `json:"user_type,omitempty"` // "user" or "bot"
}

// User represents a user
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	UserType string `json:"user_type"`
	IsActive bool   `json:"is_active"`
	IsAdmin  bool   `json:"is_admin"`
	Created  string `json:"created"`
}

// Message represents a chat message
type Message struct {
	ID        int       `json:"id"`
	Content   string    `json:"content"`
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"`
	RoomID    int       `json:"room_id"`
	RoomName  string    `json:"room_name"`
	Timestamp time.Time `json:"timestamp"`
	Edited    bool      `json:"edited"`
	EditedAt  *time.Time `json:"edited_at"`
}

// SendMessageRequest represents a message sending request
type SendMessageRequest struct {
	Content string `json:"content"`
	RoomID  int    `json:"room_id,omitempty"`
}

// Room represents a chat room
type Room struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsPrivate   bool   `json:"is_private"`
	CreatedBy   int    `json:"created_by"`
	Created     string `json:"created"`
}

// File represents an uploaded file
type File struct {
	ID       int    `json:"id"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	MimeType string `json:"mime_type"`
	UserID   int    `json:"user_id"`
	Uploaded string `json:"uploaded"`
	URL      string `json:"url"`
}

// SecurityTestRequest represents a security test request
type SecurityTestRequest struct {
	Endpoint     string            `json:"endpoint"`
	Method       string            `json:"method"`
	Payload      string            `json:"payload"`
	Headers      map[string]string `json:"headers,omitempty"`
	TestType     string            `json:"test_type"`
	ExpectedCode int               `json:"expected_code,omitempty"`
}

// SecurityTestResponse represents a security test response
type SecurityTestResponse struct {
	TestID       string `json:"test_id"`
	Endpoint     string `json:"endpoint"`
	Method       string `json:"method"`
	StatusCode   int    `json:"status_code"`
	ResponseTime int64  `json:"response_time_ms"`
	Vulnerable   bool   `json:"vulnerable"`
	Severity     string `json:"severity"`
	Description  string `json:"description"`
	Evidence     string `json:"evidence"`
	Remediation  string `json:"remediation"`
}

// BenchmarkRequest represents a benchmark test request
type BenchmarkRequest struct {
	Endpoint        string `json:"endpoint"`
	Method          string `json:"method"`
	Duration        string `json:"duration"`
	ConcurrentUsers int    `json:"concurrent_users"`
	RequestsPerSec  int    `json:"requests_per_sec,omitempty"`
}

// BenchmarkResponse represents a benchmark test response
type BenchmarkResponse struct {
	TestID           string  `json:"test_id"`
	Endpoint         string  `json:"endpoint"`
	Duration         string  `json:"duration"`
	TotalRequests    int64   `json:"total_requests"`
	SuccessfulReqs   int64   `json:"successful_requests"`
	FailedRequests   int64   `json:"failed_requests"`
	AvgResponseTime  float64 `json:"avg_response_time_ms"`
	MinResponseTime  float64 `json:"min_response_time_ms"`
	MaxResponseTime  float64 `json:"max_response_time_ms"`
	RequestsPerSec   float64 `json:"requests_per_second"`
	ThroughputMBps   float64 `json:"throughput_mbps"`
	ErrorRate        float64 `json:"error_rate_percent"`
}

// AdminStats represents admin statistics
type AdminStats struct {
	TotalUsers       int     `json:"total_users"`
	ActiveUsers      int     `json:"active_users"`
	TotalMessages    int     `json:"total_messages"`
	TotalRooms       int     `json:"total_rooms"`
	TotalFiles       int     `json:"total_files"`
	SystemUptime     string  `json:"system_uptime"`
	MemoryUsage      float64 `json:"memory_usage_mb"`
	CPUUsage         float64 `json:"cpu_usage_percent"`
	DiskUsage        float64 `json:"disk_usage_percent"`
	ActiveConnections int    `json:"active_connections"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled            bool `json:"enabled"`
	RequestsPerMinute  int  `json:"requests_per_minute"`
	BurstLimit         int  `json:"burst_limit"`
	UserRequestsPerMin int  `json:"user_requests_per_minute"`
	BotRequestsPerMin  int  `json:"bot_requests_per_minute"`
	AdminRequestsPerMin int `json:"admin_requests_per_minute"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	RequireHTTPS       bool   `json:"require_https"`
	MaxLoginAttempts   int    `json:"max_login_attempts"`
	LockoutDuration    string `json:"lockout_duration"`
	PasswordMinLength  int    `json:"password_min_length"`
	RequireStrongPass  bool   `json:"require_strong_password"`
	SessionTimeout     string `json:"session_timeout"`
	EnableIPBlacklist  bool   `json:"enable_ip_blacklist"`
	EnableThreatDetect bool   `json:"enable_threat_detection"`
}

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
	UserID    int         `json:"user_id,omitempty"`
	RoomID    int         `json:"room_id,omitempty"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
	Details string `json:"details,omitempty"`
}

// ListResponse represents a paginated list response
type ListResponse struct {
	Items      interface{} `json:"items"`
	Total      int         `json:"total"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	TotalPages int         `json:"total_pages"`
	HasNext    bool        `json:"has_next"`
	HasPrev    bool        `json:"has_prev"`
}

// MessageListResponse represents a paginated message list
type MessageListResponse struct {
	Messages   []Message `json:"items"`
	Total      int       `json:"total"`
	Page       int       `json:"page"`
	PageSize   int       `json:"page_size"`
	TotalPages int       `json:"total_pages"`
	HasNext    bool      `json:"has_next"`
	HasPrev    bool      `json:"has_prev"`
}

// RoomListResponse represents a paginated room list
type RoomListResponse struct {
	Rooms      []Room `json:"items"`
	Total      int    `json:"total"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
	TotalPages int    `json:"total_pages"`
	HasNext    bool   `json:"has_next"`
	HasPrev    bool   `json:"has_prev"`
}

// FileListResponse represents a paginated file list
type FileListResponse struct {
	Files      []File `json:"items"`
	Total      int    `json:"total"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
	TotalPages int    `json:"total_pages"`
	HasNext    bool   `json:"has_next"`
	HasPrev    bool   `json:"has_prev"`
}

// UserListResponse represents a paginated user list
type UserListResponse struct {
	Users      []User `json:"items"`
	Total      int    `json:"total"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
	TotalPages int    `json:"total_pages"`
	HasNext    bool   `json:"has_next"`
	HasPrev    bool   `json:"has_prev"`
}
