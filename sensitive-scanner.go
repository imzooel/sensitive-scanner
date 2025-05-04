package main

import (
    "bufio"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "regexp"
    "strings"
    "sync"
)

// Pattern defines a regex pattern and its associated severity
type Pattern struct {
    Name     string
    Regex    *regexp.Regexp
    Severity string
}

// Finding represents a detected sensitive data entry
type Finding struct {
    URL      string `json:"url"`
    Match    string `json:"match"`
    Severity string `json:"severity"`
    Pattern  string `json:"pattern"`
}

// ScannerConfig holds the configuration for the scanner
type ScannerConfig struct {
    Patterns       []Pattern
    Concurrency    int
    OutputFile     string
    BeautifyJS     bool
    Verbose        bool
}

// NewScannerConfig initializes the scanner configuration
func NewScannerConfig() *ScannerConfig {
    return &ScannerConfig{
        Patterns: []Pattern{
            {
                Name:     "Stripe Key",
                Regex:    regexp.MustCompile(`pk[-_]?live\s*[:=\"\'\s]*\s*([a-zA-Z0-9_\-]{8,}[^\'\":;\s,]*)`),
                Severity: "Medium",
            },
            {
                Name:     "API Key",
                Regex:    regexp.MustCompile(`api[-_]?key\s*[:=\"\'\s]*\s*([a-zA-Z0-9_\-]{8,}[^\'\":;\s,]*)`),
                Severity: "High",
            },
            {
                Name:     "App Token",
                Regex:    regexp.MustCompile(`app[-_]?token\s*[:=\"\'\s]*\s*([a-zA-Z0-9_\-]{8,}[^\'\":;\s,]*)`),
                Severity: "High",
            },
            {
                Name:     "Client ID",
                Regex:    regexp.MustCompile(`client[-_]?id\s*[:=\"\'\s]*\s*([a-zA-Z0-9_\-]{8,}[^\'\":;\s,]*)`),
                Severity: "High",
            },
        },
        Concurrency: 5,
        BeautifyJS:  true,
        Verbose:     false,
    }
}

// fetchJS fetches the content of a JS file from a URL
func fetchJS(url string) (string, error) {
    resp, err := http.Get(url)
    if err != nil {
        return "", fmt.Errorf("failed to fetch URL %s: %v", url, err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("unexpected status code for URL %s: %d", url, resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("failed to read response body from URL %s: %v", url, err)
    }

    return string(body), nil
}

// beautifyJS performs basic JS beautification (simplified for this example)
func beautifyJS(content string) string {
    // In a real implementation, you'd use a proper JS parser or external tool.
    // For simplicity, we'll just replace some common minification patterns.
    content = strings.ReplaceAll(content, ";", ";\n")
    content = strings.ReplaceAll(content, "{", "{\n")
    content = strings.ReplaceAll(content, "}", "}\n")
    return content
}

// scanURL scans a single URL for sensitive data
func scanURL(url string, config *ScannerConfig, findingsChan chan<- Finding, wg *sync.WaitGroup) {
    defer wg.Done()

    if config.Verbose {
        log.Printf("Scanning URL: %s", url)
    }

    // Fetch JS content
    content, err := fetchJS(url)
    if err != nil {
        log.Printf("Error fetching URL %s: %v", url, err)
        return
    }

    // Beautify JS if enabled
    if config.BeautifyJS {
        content = beautifyJS(content)
    }

    // Scan for sensitive data using each pattern
    for _, pattern := range config.Patterns {
        matches := pattern.Regex.FindAllStringSubmatch(content, -1)
        for _, match := range matches {
            if len(match) > 1 {
                finding := Finding{
                    URL:      url,
                    Match:    match[1], // Captured group (the sensitive data)
                    Severity: pattern.Severity,
                    Pattern:  pattern.Name,
                }
                findingsChan <- finding
            }
        }
    }
}

// saveFindings saves the findings to a file in JSON format
func saveFindings(findings []Finding, outputFile string) error {
    data, err := json.MarshalIndent(findings, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal findings: %v", err)
    }

    return os.WriteFile(outputFile, data, 0644)
}

func main() {
    // Define command-line flags
    url := flag.String("url", "", "Single URL to scan")
    urlFile := flag.String("url-file", "", "File containing list of URLs to scan")
    concurrency := flag.Int("concurrency", 5, "Number of concurrent scans")
    outputFile := flag.String("output", "", "Output file for results (JSON format)")
    beautify := flag.Bool("beautify", true, "Beautify JS files before scanning")
    verbose := flag.Bool("verbose", false, "Enable verbose logging")
    flag.Parse()

    // Validate input
    if *url == "" && *urlFile == "" {
        log.Fatal("Either -url or -url-file must be provided")
    }

    // Initialize scanner configuration
    config := NewScannerConfig()
    config.Concurrency = *concurrency
    config.OutputFile = *outputFile
    config.BeautifyJS = *beautify
    config.Verbose = *verbose

    // Collect URLs to scan
    var urls []string
    if *url != "" {
        urls = append(urls, *url)
    }
    if *urlFile != "" {
        file, err := os.Open(*urlFile)
        if err != nil {
            log.Fatalf("Failed to open URL file: %v", err)
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            url := strings.TrimSpace(scanner.Text())
            if url != "" {
                urls = append(urls, url)
            }
        }
        if err := scanner.Err(); err != nil {
            log.Fatalf("Error reading URL file: %v", err)
        }
    }

    // Set up concurrency
    var wg sync.WaitGroup
    findingsChan := make(chan Finding, 100)
    semaphore := make(chan struct{}, config.Concurrency)
    var findings []Finding

    // Start a goroutine to collect findings
    go func() {
        for finding := range findingsChan {
            findings = append(findings, finding)
        }
    }()

    // Scan each URL
    for _, url := range urls {
        wg.Add(1)
        semaphore <- struct{}{} // Acquire semaphore
        go func(url string) {
            defer func() { <-semaphore }() // Release semaphore
            scanURL(url, config, findingsChan, &wg)
        }(url)
    }

    // Wait for all scans to complete and close the findings channel
    wg.Wait()
    close(findingsChan)

    // Wait for all findings to be collected
    for len(findingsChan) > 0 {
    }

    // Output results
    for _, finding := range findings {
        fmt.Printf("[ALERT] Found sensitive data in %s\n", finding.URL)
        fmt.Printf("Match: %s\n", finding.Match)
        fmt.Printf("Severity: %s\n", finding.Severity)
        fmt.Printf("Pattern: %s\n\n", finding.Pattern)
    }

    // Save to file if specified
    if config.OutputFile != "" {
        if err := saveFindings(findings, config.OutputFile); err != nil {
            log.Fatalf("Failed to save findings: %v", err)
        }
        if config.Verbose {
            log.Printf("Findings saved to %s", config.OutputFile)
        }
    }
}