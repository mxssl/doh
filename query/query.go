package query

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/likexian/whois"
)

type dohResponse struct {
	Status   int  `json:"Status"`
	Tc       bool `json:"TC"`
	Rd       bool `json:"RD"`
	Ra       bool `json:"RA"`
	Ad       bool `json:"AD"`
	Cd       bool `json:"CD"`
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// JSONOutput represents the output structure for JSON format
type JSONOutput struct {
	Records []DNSRecord `json:"records,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// DNSRecord represents a single DNS record in JSON output
type DNSRecord struct {
	Name  string `json:"name"`
	Type  int    `json:"type"`
	TTL   int    `json:"ttl"`
	Data  string `json:"data"`
	Whois string `json:"whois,omitempty"`
}

// Provider URLs for DNS-over-HTTPS
var providerURLs = map[string]string{
	"cloudflare": "https://cloudflare-dns.com/dns-query",
	"google":     "https://dns.google/resolve",
}

// DefaultProvider is the default DoH provider
const DefaultProvider = "cloudflare"

// ValidProviders returns a list of valid provider names
func ValidProviders() []string {
	providers := make([]string, 0, len(providerURLs))
	for p := range providerURLs {
		providers = append(providers, p)
	}
	return providers
}

// GetProviderURL returns the DoH URL for the given provider
func GetProviderURL(provider string) (string, error) {
	url, ok := providerURLs[provider]
	if !ok {
		return "", fmt.Errorf("unknown provider: %s (valid providers: cloudflare, google)", provider)
	}
	return url, nil
}

// DNS record types that contain IP addresses suitable for WHOIS lookup
var ipRecordTypes = map[int]bool{
	1:  true, // A record
	28: true, // AAAA record
}

func Whois(domain string) (string, error) {
	client := whois.NewClient()
	client.SetTimeout(5 * time.Second)

	result, err := client.Whois(domain)
	if err != nil {
		return "", err
	}
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "OrgName:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "OrgName:")), nil
		}
		if strings.HasPrefix(line, "org-name:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "org-name:")), nil
		}
	}
	return "", fmt.Errorf("OrgName not found in WHOIS lookup result")
}

// OutputJSONError prints an error in JSON format (exported for cmd package)
func OutputJSONError(err error) {
	output := JSONOutput{
		Error: err.Error(),
	}
	jsonBytes, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(jsonBytes))
}

// outputJSON prints DNS records in JSON format
func outputJSON(records []DNSRecord) error {
	output := JSONOutput{
		Records: records,
	}
	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal error: %w", err)
	}
	fmt.Println(string(jsonBytes))
	return nil
}

func Do(queryType string, domain string, enableWhois bool, enableJSON bool, provider string) error {
	dohURL, err := GetProviderURL(provider)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s?name=%s&type=%s", dohURL, domain, queryType)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("new request error: %w", err)
	}

	req.Header.Set("accept", "application/dns-json")

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request do error: %w", err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			fmt.Printf("failed to close response body: %v\n", err)
		}
	}()

	content, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("read body error: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("error response status: %s, body: %s", response.Status, string(content))
	}

	var res dohResponse
	if err := json.Unmarshal(content, &res); err != nil {
		return fmt.Errorf("unmarshal error: %w", err)
	}

	if res.Status != 0 {
		return fmt.Errorf("rcode: %d, check https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6", res.Status)
	}

	if res.Answer == nil {
		if enableJSON {
			return outputJSON([]DNSRecord{})
		}
		fmt.Println("There is no such DNS record")
		return nil
	}

	// JSON output mode
	if enableJSON {
		var records []DNSRecord
		for _, r := range res.Answer {
			record := DNSRecord{
				Name: r.Name,
				Type: r.Type,
				TTL:  r.TTL,
				Data: r.Data,
			}

			// Only perform WHOIS lookup for IP address records if enabled
			if enableWhois && ipRecordTypes[r.Type] {
				whoisResult, err := Whois(r.Data)
				if err == nil && whoisResult != "" {
					record.Whois = whoisResult
				}
			}

			records = append(records, record)
		}
		return outputJSON(records)
	}

	// Colored text output mode (existing code)
	green := color.New(color.FgGreen).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()
	for _, r := range res.Answer {
		fmt.Printf("%s: %v\n", blue("name"), green(r.Name))
		fmt.Printf("%s: %v\n", blue("type"), green(r.Type))
		fmt.Printf("%s: %v\n", blue("ttl"), green(r.TTL))
		fmt.Printf("%s: %v\n", blue("data"), green(r.Data))

		// Only perform WHOIS lookup for IP address records (A and AAAA) if enabled
		if enableWhois && ipRecordTypes[r.Type] {
			whois, err := Whois(r.Data)
			if err == nil && whois != "" {
				fmt.Printf("%s: %v\n", blue("whois"), green(whois))
			}
		}
	}
	return nil
}
