package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"fux/config"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"os"
	"regexp"
	"strings"
)

// ParseRawRequest parses a raw HTTP request from a file (Burp/Caido format)
func ParseRawRequest(filename string) (*config.RawRequest, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read request file: %w", err)
	}

	return ParseRawRequestBytes(data)
}

// ParseRawRequestBytes parses raw HTTP request bytes
func ParseRawRequestBytes(data []byte) (*config.RawRequest, error) {
	req := &config.RawRequest{
		Headers:     make(map[string]string),
		OtherFields: make(map[string]string),
		Scheme:      "https",
	}

	// Split headers and body
	parts := bytes.SplitN(data, []byte("\r\n\r\n"), 2)
	if len(parts) < 2 {
		// Try with just \n\n
		parts = bytes.SplitN(data, []byte("\n\n"), 2)
	}

	headerSection := string(parts[0])
	if len(parts) > 1 {
		req.Body = parts[1]
	}

	// Parse request line and headers
	scanner := bufio.NewScanner(strings.NewReader(headerSection))

	// First line is the request line
	if scanner.Scan() {
		requestLine := scanner.Text()
		lineParts := strings.SplitN(requestLine, " ", 3)
		if len(lineParts) >= 2 {
			req.Method = lineParts[0]
			req.Path = lineParts[1]
		}
	}

	// Parse headers
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			req.Headers[key] = value

			// Extract important headers
			switch strings.ToLower(key) {
			case "host":
				req.Host = value
			case "content-type":
				req.ContentType = value
				// Extract boundary if multipart
				if strings.Contains(value, "boundary=") {
					mediaType, params, err := mime.ParseMediaType(value)
					if err == nil && strings.HasPrefix(mediaType, "multipart/") {
						req.Boundary = params["boundary"]
					}
				}
			}
		}
	}

	// Parse multipart body to extract file info
	if req.Boundary != "" && len(req.Body) > 0 {
		err := parseMultipartBody(req)
		if err != nil {
			// Non-fatal, we can still proceed
			fmt.Printf("[WARN] Could not parse multipart body: %v\n", err)
		}
	}

	return req, nil
}

// parseMultipartBody extracts file information from multipart form data
func parseMultipartBody(req *config.RawRequest) error {
	reader := multipart.NewReader(bytes.NewReader(req.Body), req.Boundary)

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Try manual parsing if standard parsing fails
			return parseMultipartManual(req)
		}

		formName := part.FormName()
		fileName := part.FileName()

		// Check if this is a file field
		if fileName != "" {
			req.FileParam = formName
			req.FileName = fileName
			content, err := io.ReadAll(part)
			if err == nil {
				req.FileContent = content
			}
		} else if formName != "" {
			// Store other form fields
			content, err := io.ReadAll(part)
			if err == nil {
				req.OtherFields[formName] = string(content)
			}
		}
	}

	return nil
}

// parseMultipartManual manually parses multipart data when standard parsing fails
func parseMultipartManual(req *config.RawRequest) error {
	body := string(req.Body)
	boundary := "--" + req.Boundary

	// Find Content-Disposition with filename
	filenameRegex := regexp.MustCompile(`Content-Disposition:\s*form-data;\s*name="([^"]+)";\s*filename="([^"]+)"`)
	matches := filenameRegex.FindStringSubmatch(body)

	if len(matches) >= 3 {
		req.FileParam = matches[1]
		req.FileName = matches[2]
	}

	// Extract file content between boundaries
	parts := strings.Split(body, boundary)
	for _, part := range parts {
		if strings.Contains(part, "filename=") {
			// Find the content after double newline
			contentIdx := strings.Index(part, "\r\n\r\n")
			if contentIdx == -1 {
				contentIdx = strings.Index(part, "\n\n")
			}
			if contentIdx > 0 {
				content := part[contentIdx+4:]
				// Remove trailing boundary markers
				content = strings.TrimSuffix(content, "--")
				content = strings.TrimSuffix(content, "\r\n")
				content = strings.TrimSuffix(content, "\n")
				req.FileContent = []byte(content)
			}
		} else if strings.Contains(part, "name=") && !strings.Contains(part, "filename=") {
			// This is a regular form field
			nameMatch := regexp.MustCompile(`name="([^"]+)"`).FindStringSubmatch(part)
			if len(nameMatch) >= 2 {
				fieldName := nameMatch[1]
				contentIdx := strings.Index(part, "\r\n\r\n")
				if contentIdx == -1 {
					contentIdx = strings.Index(part, "\n\n")
				}
				if contentIdx > 0 {
					content := strings.TrimSpace(part[contentIdx+4:])
					content = strings.TrimSuffix(content, "--")
					content = strings.TrimSpace(content)
					req.OtherFields[fieldName] = content
				}
			}
		}
	}

	return nil
}

// BuildMultipartBody builds a new multipart body with the given payload
func BuildMultipartBody(req *config.RawRequest, payload config.BypassPayload) ([]byte, string) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Use existing boundary if possible for consistency
	if req.Boundary != "" {
		err := writer.SetBoundary(req.Boundary)
		if err != nil {
			// If boundary is invalid, let multipart generate a new one
			writer = multipart.NewWriter(&buf)
		}
	}

	// Create file part FIRST (important for some servers)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, req.FileParam, payload.FileName))

	// Set Content-Type if specified in payload
	if payload.ContentType != "" {
		h.Set("Content-Type", payload.ContentType)
	}

	part, err := writer.CreatePart(h)
	if err == nil {
		part.Write(payload.Content)
	}

	// Add other form fields AFTER file (maintain original order)
	for name, value := range req.OtherFields {
		err := writer.WriteField(name, value)
		if err != nil {
			continue
		}
	}

	writer.Close()

	return buf.Bytes(), writer.FormDataContentType()
}

// RebuildRequestWithPayload rebuilds the full HTTP request with a new payload
func RebuildRequestWithPayload(req *config.RawRequest, payload config.BypassPayload) ([]byte, error) {
	var buf bytes.Buffer

	// Build new multipart body
	newBody, contentType := BuildMultipartBody(req, payload)

	// Write request line
	buf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", req.Method, req.Path))

	// Track if we've written content-type and content-length
	contentTypeWritten := false
	contentLengthWritten := false

	// Write headers
	for key, value := range req.Headers {
		lowerKey := strings.ToLower(key)

		// Update Content-Type for multipart
		if lowerKey == "content-type" {
			buf.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
			contentTypeWritten = true
		} else if lowerKey == "content-length" {
			buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(newBody)))
			contentLengthWritten = true
		} else {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}

	// Add headers if not present
	if !contentTypeWritten {
		buf.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	}
	if !contentLengthWritten {
		buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(newBody)))
	}

	// End headers
	buf.WriteString("\r\n")

	// Write body
	buf.Write(newBody)

	return buf.Bytes(), nil
}

// GetTargetURL constructs the full target URL from the request
func GetTargetURL(req *config.RawRequest) string {
	scheme := req.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", scheme, req.Host, req.Path)
}
