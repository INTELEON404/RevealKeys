package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	thread       *int
	silent       *bool
	ua           *string
	rc           *string
	detailed     *bool
	secrets      map[string]bool = make(map[string]bool)
	secretsMux   sync.Mutex
	extrapattern *string
	minEntropy   *float64
	noEntropy    *bool
	stats        ScanStats
)

// ScanStats tracks scanning statistics
type ScanStats struct {
	URLsProcessed int
	SecretsFound  int
	StartTime     time.Time
	mu            sync.Mutex
}

// SecretPattern represents a secret detection pattern with metadata
type SecretPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	MinEntropy  float64
	Category    string
	Severity    string
}

// calculateEntropy calculates Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}
	
	var entropy float64
	length := float64(len(s))
	
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	
	return entropy
}

// hasHighEntropy checks if string has sufficient randomness
func hasHighEntropy(s string, minEntropy float64) bool {
	parts := regexp.MustCompile(`[=:]\s*['"]?([^'"}\s]+)['"]?`).FindStringSubmatch(s)
	if len(parts) > 1 {
		s = parts[1]
	}
	
	return calculateEntropy(s) >= minEntropy
}

// containsCommonWords checks for false positive indicators
func containsCommonWords(s string) bool {
	lowerS := strings.ToLower(s)
	falsePositives := []string{
		"example", "test", "demo", "sample", "placeholder", "your_", "my_",
		"<", ">", "xxx", "***", "...", "todo", "fixme", "lorem", "ipsum",
		"12345", "abcde", "qwerty", "admin", "root", "change", "replace",
	}
	
	for _, fp := range falsePositives {
		if strings.Contains(lowerS, fp) {
			return true
		}
	}
	return false
}

// isLikelyFalsePositive performs multiple checks
func isLikelyFalsePositive(s string, requireEntropy bool, minEnt float64) bool {
	if containsCommonWords(s) {
		return true
	}
	
	if len(s) < 10 {
		return true
	}
	
	if requireEntropy && !hasHighEntropy(s, minEnt) {
		return true
	}
	
	if regexp.MustCompile(`(.)\1{5,}`).MatchString(s) {
		return true
	}
	
	return false
}

// initializePatterns creates all secret detection patterns
func initializePatterns() []SecretPattern {
	// High-confidence patterns first
	highConfidencePatterns := []SecretPattern{
		{
			Name:       "AWS Access Key ID",
			Pattern:    regexp.MustCompile(`(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
			MinEntropy: 3.5,
			Category:   "AWS",
			Severity:   "CRITICAL",
		},
		{
			Name:       "GitHub Personal Access Token",
			Pattern:    regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
			MinEntropy: 4.0,
			Category:   "GitHub",
			Severity:   "CRITICAL",
		},
		{
			Name:       "GitHub OAuth Token",
			Pattern:    regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
			MinEntropy: 4.0,
			Category:   "GitHub",
			Severity:   "CRITICAL",
		},
		{
			Name:       "GitHub App Token",
			Pattern:    regexp.MustCompile(`(ghu|ghs)_[0-9a-zA-Z]{36}`),
			MinEntropy: 4.0,
			Category:   "GitHub",
			Severity:   "CRITICAL",
		},
		{
			Name:       "GitHub Refresh Token",
			Pattern:    regexp.MustCompile(`ghr_[0-9a-zA-Z]{76}`),
			MinEntropy: 4.0,
			Category:   "GitHub",
			Severity:   "CRITICAL",
		},
		{
			Name:       "Slack Token",
			Pattern:    regexp.MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})`),
			MinEntropy: 3.5,
			Category:   "Slack",
			Severity:   "HIGH",
		},
		{
			Name:       "Slack Webhook",
			Pattern:    regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),
			MinEntropy: 0.0,
			Category:   "Slack",
			Severity:   "HIGH",
		},
		{
			Name:       "Google API Key",
			Pattern:    regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			MinEntropy: 3.5,
			Category:   "Google",
			Severity:   "HIGH",
		},
		{
			Name:       "Stripe Live Secret Key",
			Pattern:    regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
			MinEntropy: 4.0,
			Category:   "Stripe",
			Severity:   "CRITICAL",
		},
		{
			Name:       "Stripe Restricted Key",
			Pattern:    regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24,}`),
			MinEntropy: 4.0,
			Category:   "Stripe",
			Severity:   "CRITICAL",
		},
		{
			Name:       "SendGrid API Key",
			Pattern:    regexp.MustCompile(`SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`),
			MinEntropy: 4.0,
			Category:   "SendGrid",
			Severity:   "HIGH",
		},
		{
			Name:       "NPM Access Token",
			Pattern:    regexp.MustCompile(`npm_[0-9a-zA-Z]{36}`),
			MinEntropy: 3.5,
			Category:   "NPM",
			Severity:   "HIGH",
		},
		{
			Name:       "JWT Token",
			Pattern:    regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
			MinEntropy: 3.5,
			Category:   "JWT",
			Severity:   "MEDIUM",
		},
		{
			Name:       "RSA Private Key",
			Pattern:    regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			MinEntropy: 0.0,
			Category:   "Private Key",
			Severity:   "CRITICAL",
		},
		{
			Name:       "Private Key",
			Pattern:    regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
			MinEntropy: 0.0,
			Category:   "Private Key",
			Severity:   "CRITICAL",
		},
		{
			Name:       "OpenSSH Private Key",
			Pattern:    regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
			MinEntropy: 0.0,
			Category:   "Private Key",
			Severity:   "CRITICAL",
		},
	}

	// Original patterns from source (with smart filtering)
	var originalPatternsStrings = []string{
		`COGNITO_IDENTITY[A-Z0-9_]*:\s*"[^"]+"`,
		`REACT_APP_[A-Z_]+:\s*"([^"]+)"`,
		"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
		"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
		"[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
		"key-[0-9a-zA-Z]{32}",
		"[0-9a-f]{32}-us[0-9]{1,2}",
		"sk_live_[0-9a-z]{32}",
		"AIza[0-9A-Za-z-_]{35}",
		"6L[0-9A-Za-z-_]{38}",
		"ya29\\.[0-9A-Za-z\\-_]+",
		"AKIA[0-9A-Z]{16}",
		"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
		"s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com",
		"EAACEdEose0cBA[0-9A-Za-z]+",
		"SK[0-9a-fA-F]{32}",
		"AC[a-zA-Z0-9_\\-]{32}",
		"AP[a-zA-Z0-9_\\-]{32}",
		"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
		"sq0csp-[0-9A-Za-z\\-_]{43}",
		"sqOatp-[0-9A-Za-z\\-_]{22}",
		"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*",
		"-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END RSA PRIVATE KEY-----",
	}

	patterns := highConfidencePatterns
	
	// Add original patterns as medium-confidence
	for _, patternStr := range originalPatternsStrings {
		if pattern, err := regexp.Compile(patternStr); err == nil {
			patterns = append(patterns, SecretPattern{
				Name:       "Pattern Match",
				Pattern:    pattern,
				MinEntropy: 3.0,
				Category:   "Generic",
				Severity:   "MEDIUM",
			})
		}
	}

	return patterns
}

// cleanSecret removes quotes and whitespace from extracted secret
func cleanSecret(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "'\"")
	return s
}

// analyzeContent scans content for secrets
func analyzeContent(content string, patterns []SecretPattern, extraPattern string) []map[string]string {
	var findings []map[string]string
	lines := strings.Split(content, "\n")
	
	for _, pattern := range patterns {
		matches := pattern.Pattern.FindAllString(content, -1)
		
		for _, match := range matches {
			cleanMatch := cleanSecret(match)
			
			secretsMux.Lock()
			if secrets[cleanMatch] {
				secretsMux.Unlock()
				continue
			}
			secretsMux.Unlock()
			
			requireEntropy := pattern.MinEntropy > 0 && !*noEntropy
			if isLikelyFalsePositive(cleanMatch, requireEntropy, pattern.MinEntropy) {
				continue
			}
			
			if requireEntropy && !hasHighEntropy(cleanMatch, pattern.MinEntropy) {
				continue
			}
			
			secretsMux.Lock()
			secrets[cleanMatch] = true
			secretsMux.Unlock()
			
			lineNum := 0
			for i, line := range lines {
				if strings.Contains(line, match) {
					lineNum = i + 1
					break
				}
			}
			
			findings = append(findings, map[string]string{
				"secret":   cleanMatch,
				"type":     pattern.Name,
				"line":     strconv.Itoa(lineNum),
				"category": pattern.Category,
				"severity": pattern.Severity,
			})
		}
	}
	
	// Check extra pattern
	if len(extraPattern) > 0 {
		extraRegex, err := regexp.Compile(extraPattern)
		if err == nil {
			matches := extraRegex.FindAllString(content, -1)
			for _, match := range matches {
				cleanMatch := cleanSecret(match)
				
				secretsMux.Lock()
				alreadyFound := secrets[cleanMatch]
				if !alreadyFound {
					secrets[cleanMatch] = true
				}
				secretsMux.Unlock()
				
				if !alreadyFound {
					lineNum := 0
					for i, line := range lines {
						if strings.Contains(line, match) {
							lineNum = i + 1
							break
						}
					}
					
					findings = append(findings, map[string]string{
						"secret":   cleanMatch,
						"type":     "Custom Pattern",
						"line":     strconv.Itoa(lineNum),
						"category": "Custom",
						"severity": "CUSTOM",
					})
				}
			}
		}
	}
	
	return findings
}

// getSeverityColor returns color code based on severity
func getSeverityColor(severity string) string {
	switch severity {
	case "CRITICAL":
		return "\033[1;31m" // Bright Red
	case "HIGH":
		return "\033[1;33m" // Bright Yellow
	case "MEDIUM":
		return "\033[1;36m" // Bright Cyan
	case "CUSTOM":
		return "\033[1;35m" // Bright Magenta
	default:
		return "\033[1;32m" // Bright Green
	}
}

func req(url string) {
	if !strings.Contains(url, "http") {
		if !*silent {
			fmt.Println("\033[31m[-]\033[37m Send URLs via stdin (ex: cat js.txt | mantra)")
		}
		return
	}

	patterns := initializePatterns()

	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()
	
	transp := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpclient := &http.Client{
		Transport: transp,
		Timeout:   10 * time.Second,
	}
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	
	req.Header.Set("User-Agent", *ua)
	if len(*rc) > 0 {
		req.Header.Set("Cookie", *rc)
	}

	if *detailed {
		fmt.Printf("\033[33m[*]\033[37m Processing: %s\n", url)
	}

	r, err := httpclient.Do(req)
	if err != nil {
		if *detailed {
			fmt.Printf("\033[31m[-]\033[37m Error: %s - %v\n", url, err)
		}
		return
	}
	defer r.Body.Close()
	
	// Update stats
	stats.mu.Lock()
	stats.URLsProcessed++
	stats.mu.Unlock()
	
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}
	
	strbody := string(body)
	findings := analyzeContent(strbody, patterns, *extrapattern)
	
	// Update stats
	if len(findings) > 0 {
		stats.mu.Lock()
		stats.SecretsFound += len(findings)
		stats.mu.Unlock()
	}
	
	// Display findings
	for _, finding := range findings {
		sevColor := getSeverityColor(finding["severity"])
		
		if *detailed {
			fmt.Printf("%s[+]\033[37m %s\n", sevColor, url)
			fmt.Printf("    \033[37mSecret: \033[1;37m%s\033[0m\n", finding["secret"])
			fmt.Printf("    \033[37mType: \033[36m%s\033[0m\n", finding["type"])
			fmt.Printf("    \033[37mCategory: \033[35m%s\033[0m\n", finding["category"])
			fmt.Printf("    \033[37mSeverity: %s%s\033[0m\n", sevColor, finding["severity"])
			fmt.Printf("    \033[37mLine: \033[33m%s\033[0m\n\n", finding["line"])
		} else {
			if finding["severity"] == "CUSTOM" {
				fmt.Printf("%s[+]\033[37m %s %s[\033[37m%s%s]\033[37m [\033[36m%s\033[37m] \033[33m[CUSTOM PATTERN]\033[0m\n",
					sevColor,
					url,
					sevColor,
					truncateSecret(finding["secret"]),
					sevColor,
					finding["type"])
			} else {
				fmt.Printf("%s[+]\033[37m %s %s[\033[37m%s%s]\033[37m [\033[36m%s\033[37m] [\033[35m%s\033[37m]\033[0m\n",
					sevColor,
					url,
					sevColor,
					truncateSecret(finding["secret"]),
					sevColor,
					finding["type"],
					finding["severity"])
			}
		}
	}
}

// truncateSecret truncates long secrets for display
func truncateSecret(s string) string {
	if len(s) > 60 {
		return s[:30] + "..." + s[len(s)-20:]
	}
	return s
}

func init() {
	silent = flag.Bool("s", false, "silent mode (no banner)")
	thread = flag.Int("t", 50, "number of concurrent threads")
	ua = flag.String("ua", "Mantra/1.0 Security Scanner", "User-Agent header")
	detailed = flag.Bool("d", false, "detailed output with full information")
	rc = flag.String("c", "", "cookies to include in requests")
	extrapattern = flag.String("ep", "", "extra custom regex pattern")
	minEntropy = flag.Float64("me", 3.5, "minimum entropy threshold (0-8)")
	noEntropy = flag.Bool("ne", false, "disable entropy checking (more results)")
}

func banner() {
	fmt.Printf("\033[31m" + `
░█▀▄░█▀▀░█░█░█▀▀░█▀█░█░░░█░█░█▀▀░█░█░█▀▀
░█▀▄░█▀▀░▀▄▀░█▀▀░█▀█░█░░░█▀▄░█▀▀░░█░░▀▀█
░▀░▀░▀▀▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀░▀░▀▀▀░░▀░░▀▀▀
` + "\033[0m")
	fmt.Printf("\033[36m    DEVELOPMENT By:\033[37m INTELEON404\n")
}

func printStats() {
	elapsed := time.Since(stats.StartTime)
	fmt.Println("\n\033[36m" + strings.Repeat("═", 68) + "\033[0m")
	fmt.Printf("\033[1;32m                    SCAN COMPLETE\033[0m\n")
	fmt.Println("\033[36m" + strings.Repeat("═", 68) + "\033[0m")
	fmt.Printf("\033[37m  URLs Processed: \033[1;36m%d\033[0m\n", stats.URLsProcessed)
	fmt.Printf("\033[37m  Secrets Found:  \033[1;32m%d\033[0m\n", stats.SecretsFound)
	fmt.Printf("\033[37m  Time Elapsed:   \033[1;33m%s\033[0m\n", elapsed.Round(time.Second))
	if stats.URLsProcessed > 0 {
		fmt.Printf("\033[37m  Avg Speed:      \033[1;35m%.2f URLs/sec\033[0m\n", 
			float64(stats.URLsProcessed)/elapsed.Seconds())
	}
	fmt.Println("\033[36m" + strings.Repeat("═", 68) + "\033[0m")
	fmt.Printf("\033[32m  Happy Hunting! 🎯\033[0m\n\n")
}

func main() {
	flag.Parse()
	
	stats.StartTime = time.Now()

	if !*silent {
		banner()
	}

	stdin := bufio.NewScanner(os.Stdin)
	urls := make(chan string, *thread*2)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < *thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urls {
				req(url)
			}
		}()
	}

	// Read URLs from stdin
	go func() {
		for stdin.Scan() {
			url := strings.TrimSpace(stdin.Text())
			if url != "" {
				urls <- url
			}
		}
		close(urls)
	}()

	// Wait for completion
	wg.Wait()

	// Print statistics
	if !*silent {
		printStats()
	}
}
