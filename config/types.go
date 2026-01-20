package config

import "time"

// Config holds the application configuration
type Config struct {
	RequestFile    string
	TargetURL      string
	FileParam      string
	Threads        int
	Proxy          string
	Timeout        int
	VerifyUpload   bool
	OutputFile     string
	Verbose        bool
	Delay          int    // Delay between requests in milliseconds
	SkipMIME       bool   // Skip MIME type payloads
	SkipMagic      bool   // Skip magic bytes payloads
	SkipExtension  bool   // Skip extension payloads
	SkipFilename   bool   // Skip filename payloads
	SkipContent    bool   // Skip content obfuscation payloads
	SkipPolyglot   bool   // Skip polyglot payloads
	OnlyCategory   string // Only run specific category
	RandomAgent    bool   // Randomize User-Agent
	UserAgentFile  string // Path to file containing user agents
	MatchString    string // Custom string to match in response for success detection
	MatchRegex     string // Custom regex pattern to match in response
	NotMatchString string // If this string is found, consider it failed (for filtering false positives)
}

// RawRequest represents a parsed HTTP request
type RawRequest struct {
	Method      string
	Path        string
	Host        string
	Scheme      string
	Headers     map[string]string
	Body        []byte
	Boundary    string
	FileParam   string
	FileName    string
	FileContent []byte
	ContentType string
	OtherFields map[string]string // Store other form fields
}

// BypassPayload represents a single bypass attempt
type BypassPayload struct {
	Name        string // Human-readable name
	FileName    string // Modified filename
	Content     []byte // File content (possibly with magic bytes)
	ContentType string // MIME type to use
	Category    string // Bypass category (extension, mime, magic, etc.)
	Priority    int    // Priority level (higher = try first)
}

// ScanResult represents the result of a single bypass attempt
type ScanResult struct {
	Payload      BypassPayload
	Success      bool
	StatusCode   int
	ResponseSize int
	ResponseBody string
	UploadPath   string
	Verified     bool
	Error        string
	ErrorReason  string // Human-readable error reason
	RequestTime  time.Duration
	ResponseHash string // Hash of response for duplicate detection
}

// ScanStats holds scanning statistics
type ScanStats struct {
	TotalPayloads   int
	CompletedCount  int
	SuccessCount    int
	ErrorCount      int
	SkippedCount    int
	StartTime       time.Time
	UniqueSuccesses map[string]bool // Deduplicate by response hash
}

// Colors for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
	ColorBlink  = "\033[5m"
)

// Version information
const (
	Version  = "1.1.0"
	ToolName = "FUX"
	FullName = "File Upload eXploiter"
	Author   = "Security Researcher"
)
