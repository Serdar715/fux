package main

import (
	"flag"
	"fmt"
	"fux/config"
	"fux/scanner"
	"os"
	"strings"
)

func main() {
	cfg := &config.Config{}

	// Required flags
	flag.StringVar(&cfg.RequestFile, "r", "", "Raw HTTP request file (Burp/Caido)")
	flag.StringVar(&cfg.TargetURL, "u", "", "Target URL (overrides Host header)")
	flag.StringVar(&cfg.FileParam, "p", "", "File parameter name (auto-detected if not specified)")

	// Performance flags
	flag.IntVar(&cfg.Threads, "t", 10, "Number of concurrent threads")
	flag.IntVar(&cfg.Timeout, "timeout", 15, "Request timeout in seconds")
	flag.IntVar(&cfg.Delay, "delay", 0, "Delay between requests in milliseconds")
	flag.StringVar(&cfg.Proxy, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")

	// Output flags
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file for results (JSON format)")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output (show failed attempts)")
	flag.BoolVar(&cfg.VerifyUpload, "verify", false, "Verify successful uploads by accessing the file")

	// Filter flags
	flag.BoolVar(&cfg.SkipMIME, "skip-mime", false, "Skip MIME type bypass payloads")
	flag.BoolVar(&cfg.SkipMagic, "skip-magic", false, "Skip magic bytes payloads")
	flag.BoolVar(&cfg.SkipExtension, "skip-ext", false, "Skip extension bypass payloads")
	flag.BoolVar(&cfg.SkipFilename, "skip-filename", false, "Skip filename obfuscation payloads")
	flag.BoolVar(&cfg.SkipContent, "skip-content", false, "Skip content obfuscation payloads")
	flag.BoolVar(&cfg.SkipPolyglot, "skip-polyglot", false, "Skip polyglot payloads")
	flag.StringVar(&cfg.OnlyCategory, "category", "", "Only run specific category (extension,mime,magic,filename,content,polyglot)")

	// Match string flags (custom success detection)
	flag.StringVar(&cfg.MatchString, "mr", "", "Match response: consider upload successful if response contains this text")
	flag.StringVar(&cfg.MatchString, "match", "", "Match response: consider upload successful if response contains this text")
	flag.StringVar(&cfg.MatchRegex, "mre", "", "Match regex: consider upload successful if response matches this pattern")
	flag.StringVar(&cfg.NotMatchString, "nmr", "", "Not match response: consider failed if response contains this text")

	// Misc flags
	flag.BoolVar(&cfg.RandomAgent, "random-agent", false, "Randomize User-Agent header")
	flag.StringVar(&cfg.UserAgentFile, "ua", "", "Load User-Agents from file (one per line)")

	// Custom usage
	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Required:\n")
		fmt.Fprintf(os.Stderr, "  -r string\t\tRaw HTTP request file (Burp/Caido format)\n\n")
		fmt.Fprintf(os.Stderr, "Optional:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -r request.txt\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r request.txt -proxy http://127.0.0.1:8080 -v\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r request.txt -category extension -verify\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r request.txt -t 20 -delay 100 -o results.json\n", os.Args[0])
	}

	flag.Parse()

	// Validate required arguments
	if cfg.RequestFile == "" {
		fmt.Printf("%s[!] Error: Request file is required (-r)%s\n", config.ColorRed, config.ColorReset)
		fmt.Println()
		flag.Usage()
		os.Exit(1)
	}

	// Check if request file exists
	if _, err := os.Stat(cfg.RequestFile); os.IsNotExist(err) {
		fmt.Printf("%s[!] Error: Request file not found: %s%s\n", config.ColorRed, cfg.RequestFile, config.ColorReset)
		os.Exit(1)
	}

	// Validate category if specified
	if cfg.OnlyCategory != "" {
		validCategories := []string{"extension", "mime", "magic", "filename", "content", "polyglot"}
		valid := false
		for _, c := range validCategories {
			if strings.EqualFold(cfg.OnlyCategory, c) {
				valid = true
				break
			}
		}
		if !valid {
			fmt.Printf("%s[!] Error: Invalid category '%s'. Valid options: %s%s\n",
				config.ColorRed, cfg.OnlyCategory, strings.Join(validCategories, ", "), config.ColorReset)
			os.Exit(1)
		}
	}

	// Initialize and run scanner
	engine, err := scanner.NewEngine(cfg)
	if err != nil {
		fmt.Printf("%s[!] Error initializing engine: %v%s\n", config.ColorRed, err, config.ColorReset)
		os.Exit(1)
	}

	engine.StartScan()
}

func printBanner() {
	banner := `
    ███████╗██╗   ██╗██╗  ██╗
    ██╔════╝██║   ██║╚██╗██╔╝
    █████╗  ██║   ██║ ╚███╔╝ 
    ██╔══╝  ██║   ██║ ██╔██╗ 
    ██║     ╚██████╔╝██╔╝ ██╗
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝
    File Upload eXploiter v` + config.Version + `
`
	fmt.Printf("%s%s%s\n", config.ColorCyan, banner, config.ColorReset)
}
