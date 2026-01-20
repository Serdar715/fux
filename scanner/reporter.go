package scanner

import (
	"encoding/json"
	"fmt"
	"fux/config"
	"os"
	"time"
)

// Reporter handles output reporting
type Reporter struct {
	Verbose    bool
	OutputFile string
	results    []config.ScanResult
}

// NewReporter creates a new reporter
func NewReporter(verbose bool, outputFile string) *Reporter {
	return &Reporter{
		Verbose:    verbose,
		OutputFile: outputFile,
		results:    make([]config.ScanResult, 0),
	}
}

// PrintBanner prints the tool banner
func (r *Reporter) PrintBanner() {
	banner := `
    ███████╗██╗   ██╗██╗  ██╗
    ██╔════╝██║   ██║╚██╗██╔╝
    █████╗  ██║   ██║ ╚███╔╝ 
    ██╔══╝  ██║   ██║ ██╔██╗ 
    ██║     ╚██████╔╝██╔╝ ██╗
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝
    ` + config.FullName + ` v` + config.Version + `
`
	fmt.Printf("%s%s%s\n", config.ColorCyan, banner, config.ColorReset)
}

// PrintConfig prints the current configuration
func (r *Reporter) PrintConfig(cfg *config.Config, req *config.RawRequest) {
	fmt.Printf("%s[*] Configuration:%s\n", config.ColorBlue, config.ColorReset)
	fmt.Printf("    %sTarget:%s %s\n", config.ColorDim, config.ColorReset, cfg.TargetURL)
	fmt.Printf("    %sFile Param:%s %s\n", config.ColorDim, config.ColorReset, cfg.FileParam)
	fmt.Printf("    %sThreads:%s %d\n", config.ColorDim, config.ColorReset, cfg.Threads)

	if cfg.Proxy != "" {
		fmt.Printf("    %sProxy:%s %s\n", config.ColorDim, config.ColorReset, cfg.Proxy)
	}
	if cfg.MatchString != "" {
		fmt.Printf("    %sMatch String:%s %s\n", config.ColorGreen, config.ColorReset, cfg.MatchString)
	}
	if cfg.MatchRegex != "" {
		fmt.Printf("    %sMatch Regex:%s %s\n", config.ColorGreen, config.ColorReset, cfg.MatchRegex)
	}
	if cfg.NotMatchString != "" {
		fmt.Printf("    %sNot Match:%s %s\n", config.ColorRed, config.ColorReset, cfg.NotMatchString)
	}
	fmt.Println()
}

// PrintScanStart prints start information
func (r *Reporter) PrintScanStart(target string, payloadCount int) {
	fmt.Printf("%s[*] Target URL:%s %s\n", config.ColorBlue, config.ColorReset, target)
	fmt.Printf("%s[*] Loaded Payloads:%s %d\n", config.ColorBlue, config.ColorReset, payloadCount)
	fmt.Printf("%s[*] Starting scan at %s%s\n\n", config.ColorBlue, time.Now().Format("15:04:05"), config.ColorReset)
}

// ReportResult prints a single result
func (r *Reporter) ReportResult(result config.ScanResult) {
	if result.Success {
		// Found!
		fmt.Printf("\n%s[+] FOUND: %s%s\n", config.ColorGreen, config.ColorReset, result.Payload.Name)
		fmt.Printf("    %sCategory:%s %s\n", config.ColorGreen, config.ColorReset, result.Payload.Category)
		fmt.Printf("    %sFile:%s %s\n", config.ColorGreen, config.ColorReset, result.Payload.FileName)
		fmt.Printf("    %sMIME:%s %s\n", config.ColorGreen, config.ColorReset, result.Payload.ContentType)
		fmt.Printf("    %sStatus:%s %d | %sSize:%s %d bytes\n",
			config.ColorYellow, config.ColorReset, result.StatusCode,
			config.ColorYellow, config.ColorReset, result.ResponseSize)

		if result.UploadPath != "" {
			fmt.Printf("    %sPath:%s %s\n", config.ColorYellow, config.ColorReset, result.UploadPath)
		}

		if result.Verified {
			fmt.Printf("    %s[VERIFIED] Shell is accessible!%s\n", config.ColorGreen+config.ColorBold, config.ColorReset)
		} else if result.UploadPath != "" {
			fmt.Printf("    %s[?] Could not automatically verify access%s\n", config.ColorYellow, config.ColorReset)
		}

		fmt.Printf("    %sTime:%s %v\n", config.ColorDim, config.ColorReset, result.RequestTime.Round(time.Millisecond))
	} else if r.Verbose {
		reason := result.ErrorReason
		if reason == "" {
			reason = "Rejected"
		}
		fmt.Printf("%s[-] %s: %s (%d) - %s%s\n",
			config.ColorRed, result.Payload.Name, result.Payload.FileName,
			result.StatusCode, reason, config.ColorReset)
	}
}

// PrintSummary prints the final summary
func (r *Reporter) PrintSummary(stats *config.ScanStats, duration time.Duration) {
	fmt.Println()
	fmt.Printf("%s══════════════════════════════════════════════%s\n", config.ColorBlue, config.ColorReset)
	fmt.Printf("%s[*] Scan Complete%s\n", config.ColorBlue+config.ColorBold, config.ColorReset)
	fmt.Printf("%s══════════════════════════════════════════════%s\n", config.ColorBlue, config.ColorReset)
	fmt.Printf("    %sDuration:%s %v\n", config.ColorDim, config.ColorReset, duration.Round(time.Second))
	fmt.Printf("    %sTotal Payloads:%s %d\n", config.ColorDim, config.ColorReset, stats.TotalPayloads)
	fmt.Printf("    %sCompleted:%s %d\n", config.ColorDim, config.ColorReset, stats.CompletedCount)

	if stats.ErrorCount > 0 {
		fmt.Printf("    %sErrors:%s %d\n", config.ColorRed, config.ColorReset, stats.ErrorCount)
	}

	if stats.SuccessCount > 0 {
		fmt.Printf("\n    %s[!] Successful Uploads: %d%s\n", config.ColorGreen+config.ColorBold, stats.SuccessCount, config.ColorReset)
		fmt.Printf("    %s[!] Unique Bypasses: %d%s\n", config.ColorGreen, len(stats.UniqueSuccesses), config.ColorReset)
	} else {
		fmt.Printf("\n    %s[*] No successful uploads detected.%s\n", config.ColorYellow, config.ColorReset)
		fmt.Printf("    %sTry different payloads or check your match criteria.%s\n", config.ColorDim, config.ColorReset)
	}
}

// SaveResults saves successful results to a JSON file
func (r *Reporter) SaveResults(results []config.ScanResult, filename string) {
	if len(results) == 0 {
		fmt.Printf("%s[*] No results to save.%s\n", config.ColorYellow, config.ColorReset)
		return
	}

	// Create simplified output structure
	type OutputResult struct {
		PayloadName string `json:"payload_name"`
		Category    string `json:"category"`
		FileName    string `json:"filename"`
		ContentType string `json:"content_type"`
		StatusCode  int    `json:"status_code"`
		UploadPath  string `json:"upload_path,omitempty"`
		Verified    bool   `json:"verified"`
	}

	var output []OutputResult
	for _, res := range results {
		output = append(output, OutputResult{
			PayloadName: res.Payload.Name,
			Category:    res.Payload.Category,
			FileName:    res.Payload.FileName,
			ContentType: res.Payload.ContentType,
			StatusCode:  res.StatusCode,
			UploadPath:  res.UploadPath,
			Verified:    res.Verified,
		})
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Printf("%s[!] Error serializing results: %v%s\n", config.ColorRed, err, config.ColorReset)
		return
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("%s[!] Error writing results file: %v%s\n", config.ColorRed, err, config.ColorReset)
		return
	}

	fmt.Printf("%s[+] Results saved to: %s%s\n", config.ColorGreen, filename, config.ColorReset)
}
