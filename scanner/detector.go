package scanner

import (
	"fux/config"
	"net/http"
	"regexp"
	"strings"
)

// Detector handles the logic for detecting if an upload was successful
type Detector struct {
	BaseResponseStatus int
	BaseResponseBody   string
	Config             *config.Config
}

// NewDetector creates a new detector
func NewDetector() *Detector {
	return &Detector{}
}

// SetConfig sets the config for custom match detection
func (d *Detector) SetConfig(cfg *config.Config) {
	d.Config = cfg
}

// SetBaseResponse sets the baseline response from a legitimate request
func (d *Detector) SetBaseResponse(status int, body string) {
	d.BaseResponseStatus = status
	d.BaseResponseBody = body
}

// DetectSuccess checks if the upload was successful based on the response
func (d *Detector) DetectSuccess(resp *http.Response, body string, payload config.BypassPayload) (bool, string) {
	lowerBody := strings.ToLower(body)

	// PRIORITY 1: Check user-defined NOT match string (false positive filter)
	if d.Config != nil && d.Config.NotMatchString != "" {
		if strings.Contains(lowerBody, strings.ToLower(d.Config.NotMatchString)) {
			return false, ""
		}
	}

	// PRIORITY 2: Check user-defined match string
	if d.Config != nil && d.Config.MatchString != "" {
		if strings.Contains(lowerBody, strings.ToLower(d.Config.MatchString)) {
			return true, d.extractPath(body)
		}
		// If user specified a match string but it wasn't found, don't use other detection methods
		return false, ""
	}

	// PRIORITY 3: Check user-defined match regex
	if d.Config != nil && d.Config.MatchRegex != "" {
		re, err := regexp.Compile(d.Config.MatchRegex)
		if err == nil && re.MatchString(body) {
			return true, d.extractPath(body)
		}
		// If user specified a regex but it didn't match, don't use other detection methods
		return false, ""
	}

	// AUTO DETECTION METHODS (only used when no custom match is specified)

	// Check for explicit error keywords first (to avoid false positives)
	errorKeywords := []string{
		"not allowed",
		"invalid file",
		"invalid extension",
		"file type not",
		"upload failed",
		"error uploading",
		"rejected",
		"forbidden",
		"blocked",
		"malicious",
		"virus detected",
		"dangerous file",
	}

	for _, kw := range errorKeywords {
		if strings.Contains(lowerBody, kw) {
			return false, ""
		}
	}

	// Status Code Check (2xx = potential success)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Look for success indicators in response
		successKeywords := []string{
			"uploaded successfully",
			"upload successful",
			"file uploaded",
			"upload complete",
			"successfully uploaded",
			"has been uploaded",
			"file saved",
			"saved successfully",
			"upload succeeded",
			"file accepted",
			"upload ok",
			"success\":true",
			"\"success\": true",
			"status\":\"success",
			"\"status\": \"success",
			"result\":\"ok",
			"file received",
		}

		for _, kw := range successKeywords {
			if strings.Contains(lowerBody, kw) {
				return true, d.extractPath(body)
			}
		}

		// Check for file path patterns in response (strong indicator)
		pathPatterns := []string{
			`"url"\s*:\s*"[^"]+\.(php|phtml|asp|aspx|jsp|jpg|png|gif)`,
			`"path"\s*:\s*"[^"]+`,
			`"filename"\s*:\s*"[^"]+`,
			`/uploads/[a-zA-Z0-9._-]+`,
			`/files/[a-zA-Z0-9._-]+`,
			`/images/[a-zA-Z0-9._-]+`,
		}

		for _, pattern := range pathPatterns {
			re := regexp.MustCompile(`(?i)` + pattern)
			if re.MatchString(body) {
				return true, d.extractPath(body)
			}
		}

		// If response contains our uploaded filename, likely success
		if payload.FileName != "" {
			baseName := strings.TrimSuffix(payload.FileName, ".php")
			baseName = strings.TrimSuffix(baseName, ".jpg")
			baseName = strings.TrimSuffix(baseName, ".png")
			if len(baseName) > 3 && strings.Contains(lowerBody, strings.ToLower(baseName)) {
				return true, d.extractPath(body)
			}
		}
	}

	// Content Length Change compared to baseline (if set)
	if d.BaseResponseStatus != 0 {
		if resp.StatusCode != d.BaseResponseStatus {
			// STATUS changed - might be interesting
			// But be careful with error codes
			if resp.StatusCode != 403 && resp.StatusCode != 500 &&
				resp.StatusCode != 400 && resp.StatusCode != 401 {
				// Different status, might indicate bypass
				// Check if body also significantly changed
				if len(body) != len(d.BaseResponseBody) {
					return true, d.extractPath(body)
				}
			}
		}
	}

	return false, ""
}

// extractPath attempts to find the uploaded file path in the response
func (d *Detector) extractPath(body string) string {
	// Regex for common path patterns
	patterns := []string{
		`"url"\s*:\s*"([^"]+)"`,
		`'url'\s*:\s*'([^']+)'`,
		`"path"\s*:\s*"([^"]+)"`,
		`"file"\s*:\s*"([^"]+)"`,
		`"filename"\s*:\s*"([^"]+)"`,
		`"location"\s*:\s*"([^"]+)"`,
		`src\s*=\s*"([^"]+)"`,
		`href\s*=\s*"([^"]+)"`,
		`(/uploads/[a-zA-Z0-9._/-]+)`,
		`(/files/[a-zA-Z0-9._/-]+)`,
		`(/images/[a-zA-Z0-9._/-]+)`,
		`(/storage/[a-zA-Z0-9._/-]+)`,
		`(https?://[^\s"'<>]+\.(php|phtml|jpg|png|gif|asp|jsp)[^\s"'<>]*)`,
	}

	for _, p := range patterns {
		re := regexp.MustCompile(`(?i)` + p)
		matches := re.FindStringSubmatch(body)
		if len(matches) > 1 {
			path := matches[1]
			// Filter out obvious non-file paths
			if len(path) > 3 &&
				!strings.Contains(path, "javascript:") &&
				!strings.Contains(path, "data:") &&
				!strings.HasPrefix(path, "#") {
				return path
			}
		}
	}

	return ""
}

// AnalyzeError returns a human-readable reason for failure if possible
func (d *Detector) AnalyzeError(body string) string {
	lowerBody := strings.ToLower(body)

	errorKeywords := map[string]string{
		"extension not allowed": "Extension Blocked",
		"not allowed":           "File Type Blocked",
		"invalid file type":     "Invalid File Type",
		"invalid extension":     "Extension Blocked",
		"file type":             "File Type Check Failed",
		"mime type":             "MIME Type Blocked",
		"content-type":          "Content-Type Blocked",
		"detected":              "WAF/Security Detection",
		"virus":                 "Antivirus Detected",
		"malware":               "Malware Detection",
		"malicious":             "Deep Content Inspection",
		"blocked":               "Blocked by Security",
		"forbidden":             "Access Forbidden",
		"too large":             "File Too Large",
		"too big":               "File Size Exceeded",
		"size limit":            "Size Limit Exceeded",
		"already exists":        "File Already Exists",
		"permission denied":     "Permission Denied",
		"write error":           "Write Error",
		"internal server":       "Server Error",
		"upload error":          "Upload Error",
		"empty file":            "Empty File Rejected",
		"no file":               "No File Detected",
		"image required":        "Image Validation Failed",
		"invalid image":         "Image Validation Failed",
		"corrupted":             "File Corruption Check",
		"php":                   "PHP Content Detected",
		"script":                "Script Content Detected",
	}

	for k, v := range errorKeywords {
		if strings.Contains(lowerBody, k) {
			return v
		}
	}

	return "Unknown Rejection"
}
