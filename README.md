# SensitiveScanner

SensitiveScanner is a cybersecurity tool written in Go that scans JavaScript (JS) files for sensitive data such as API keys, access tokens, and other credentials. It leverages regular expressions (regex) to identify potentially leaked data in JS files, making it a valuable utility for bug bounty hunters, security researchers, and developers looking to secure their applications. As a junior security engineer, I built this tool to demonstrate my skills in Go programming, web security, and ethical hacking practices.


## Features

- **Multiple Regex Patterns**: Predefined patterns to detect Stripe keys (`pk_live`), API keys (`apiKey`), app tokens (`app-token`), and client IDs (`client-id`), with severity levels (Medium, High).
- **Concurrency Support**: Adjustable concurrency for faster scanning of multiple URLs.
- **Flexible Input**: Scan a single URL or a list of URLs from a file.
- **Output Options**: Results can be displayed in the console or saved to a JSON file.
- **JS Beautification**: Optional beautification of minified JS files for better regex matching.
- **Verbose Mode**: Enable detailed logging for debugging and transparency.
- **Customizable**: Easily extendable with new regex patterns or features.

## Installation

### Prerequisites

- **Go**: Version 1.21 or later. Download and install from [golang.org](https://golang.org).
- A terminal or command-line interface to build and run the tool.

### Steps

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/yourusername/sensitive-scanner.git
    cd sensitive-scanner
    ```

2. **Initialize Go Modules** (if not already done):
    ```bash
    go mod init sensitive-scanner
    ```

3. **Build the Tool**:
    ```bash
    go build -o sensitive-scanner
    ```

4. **Verify Installation**:
    Run the tool with the help flag to ensure it’s working:
    ```bash
    ./sensitive-scanner -h
    ```

## Usage

### Command-Line Flags

The tool supports the following flags:

- `-url <URL>`: Scan a single URL (e.g., `https://example.com/script.js`).
- `-url-file <file>`: Scan multiple URLs from a file (one URL per line).
- `-concurrency <int>`: Number of concurrent scans (default: 5).
- `-output <file>`: Save results to a JSON file (e.g., `results.json`).
- `-beautify`: Enable/disable JS beautification (default: true).
- `-verbose`: Enable verbose logging for debugging.

## Examples

### 1. Scan a Single URL

Scan a single JS file for sensitive data:

```bash
./sensitive-scanner -url https://example.com/script.js
```

Sample Output:

```
[ALERT] Found sensitive data in https://example.com/script.js
Match: pk_live_abc123xyz456
Severity: Medium
Pattern: Stripe Key

[ALERT] Found sensitive data in https://example.com/script.js
Match: ba62b8
Severity: High
Pattern: API Key
```

### 2. Scan Multiple URLs from a File

Create a file named `urls.txt` with URLs to scan:

```
https://example.com/script1.js
https://example.com/script2.js
```

Run the tool:

```bash
./sensitive-scanner -url-file urls.txt -concurrency 10 -output results.json -verbose
```

Sample Output (verbose mode):

```
2025-05-04 11:00:00 Scanning URL: https://example.com/script1.js
2025-05-04 11:00:01 Scanning URL: https://example.com/script2.js
[ALERT] Found sensitive data in https://example.com/script1.js
Match: apiKey_ba62b8
Severity: High
Pattern: API Key
Findings saved to results.json
```

### 3. Output to JSON

The `-output` flag saves results in JSON format:

```json
[
  {
    "url": "https://example.com/script1.js",
    "match": "apiKey_ba62b8",
    "severity": "High",
    "pattern": "API Key"
  }
]
```

## Configuration

### Adding New Regex Patterns

To add new patterns, modify the `Patterns` slice in `main.go`:

```go
{
    Name:     "AWS Key",
    Regex:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
    Severity: "Critical",
},
```

Rebuild the tool after making changes:

```bash
go build -o sensitive-scanner
```

### Adjusting Concurrency

Increase or decrease the `-concurrency` flag based on your system’s capabilities and the target server’s rate limits. For example, to scan with 20 concurrent goroutines:

```bash
./sensitive-scanner -url-file urls.txt -concurrency 20
```


## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

This tool is intended for ethical use only, such as authorized security testing or bug bounty programs. Unauthorized scanning or misuse of this tool may violate laws or terms of service. Always obtain permission before scanning any website or application, and report findings responsibly through proper channels (e.g., bug bounty platforms like HackerOne or Bugcrowd).

## Vibecoding Note

This project was generated with the assistance of Grok, an AI developed by xAI. As an independent security researcher, I used AI to accelerate development and learn best practices, but I have reviewed and understood the code to ensure it aligns with my skills and goals. This demonstrates my ability to leverage modern tools while building practical cybersecurity solutions.
