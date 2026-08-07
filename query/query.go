package query

import (
	"context"
	"encoding/json"
	"errors"
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
	Answer     []dohRecord     `json:"Answer"`
	Authority  []dohRecord     `json:"Authority"`
	Additional []dohRecord     `json:"Additional"`
	Comment    responseComment `json:"Comment"`
}

type dohRecord struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type responseComment []string

func (c *responseComment) UnmarshalJSON(data []byte) error {
	var comments []string
	if err := json.Unmarshal(data, &comments); err == nil {
		*c = comments
		return nil
	}

	var comment string
	if err := json.Unmarshal(data, &comment); err != nil {
		return fmt.Errorf("invalid DNS response comment: %w", err)
	}
	if comment != "" {
		*c = []string{comment}
	}
	return nil
}

// JSONOutput represents the output structure for JSON format
type JSONOutput struct {
	Status     int           `json:"status"`
	StatusName string        `json:"status_name"`
	Flags      DNSFlags      `json:"flags"`
	Question   []DNSQuestion `json:"question,omitempty"`
	Records    []DNSRecord   `json:"records,omitempty"`
	Authority  []DNSRecord   `json:"authority,omitempty"`
	Additional []DNSRecord   `json:"additional,omitempty"`
	Comments   []string      `json:"comments,omitempty"`
	Error      string        `json:"error,omitempty"`
}

// DNSQuestion represents the question section of a DNS response.
type DNSQuestion struct {
	Name     string `json:"name"`
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
}

// DNSFlags represents the response flags exposed by the DoH JSON APIs.
type DNSFlags struct {
	Truncated          bool `json:"tc"`
	RecursionDesired   bool `json:"rd"`
	RecursionAvailable bool `json:"ra"`
	AuthenticData      bool `json:"ad"`
	CheckingDisabled   bool `json:"cd"`
}

// DNSRecord represents a single DNS record in JSON output
type DNSRecord struct {
	Name     string `json:"name"`
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	TTL      int    `json:"ttl"`
	Data     string `json:"data"`
	Whois    string `json:"whois,omitempty"`
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

type rcodeInfo struct {
	name        string
	description string
}

var rcodeByCode = map[int][]rcodeInfo{
	0: {
		{name: "NoError", description: "No Error"},
	},
	1: {
		{name: "FormErr", description: "Format Error"},
	},
	2: {
		{name: "ServFail", description: "Server Failure"},
	},
	3: {
		{name: "NXDomain", description: "Non-Existent Domain"},
	},
	4: {
		{name: "NotImp", description: "Not Implemented"},
	},
	5: {
		{name: "Refused", description: "Query Refused"},
	},
	6: {
		{name: "YXDomain", description: "Name Exists when it should not"},
	},
	7: {
		{name: "YXRRSet", description: "RR Set Exists when it should not"},
	},
	8: {
		{name: "NXRRSet", description: "RR Set that should exist does not"},
	},
	9: {
		{name: "NotAuth", description: "Server Not Authoritative for zone"},
		{name: "NotAuth", description: "Not Authorized"},
	},
	10: {
		{name: "NotZone", description: "Name not contained in zone"},
	},
	11: {
		{name: "DSOTYPENI", description: "DSO-TYPE Not Implemented"},
	},
	16: {
		{name: "BADVERS", description: "Bad OPT Version"},
		{name: "BADSIG", description: "TSIG Signature Failure"},
	},
	17: {
		{name: "BADKEY", description: "Key not recognized"},
	},
	18: {
		{name: "BADTIME", description: "Signature out of time window"},
	},
	19: {
		{name: "BADMODE", description: "Bad TKEY Mode"},
	},
	20: {
		{name: "BADNAME", description: "Duplicate key name"},
	},
	21: {
		{name: "BADALG", description: "Algorithm not supported"},
	},
	22: {
		{name: "BADTRUNC", description: "Bad Truncation"},
	},
	23: {
		{name: "BADCOOKIE", description: "Bad/missing Server Cookie"},
	},
}

func formatRcodeError(code int) string {
	entries, exists := rcodeByCode[code]
	if exists {
		parts := make([]string, 0, len(entries))
		for _, entry := range entries {
			parts = append(parts, fmt.Sprintf("%s: %s", entry.name, entry.description))
		}
		return fmt.Sprintf("%s (rcode: %d)", strings.Join(parts, " | "), code)
	}

	if code >= 12 && code <= 15 {
		return fmt.Sprintf("Unassigned (rcode: %d)", code)
	}
	if code >= 24 && code <= 3840 {
		return fmt.Sprintf("Unassigned (rcode: %d)", code)
	}
	if code >= 3841 && code <= 4095 {
		return fmt.Sprintf("Reserved for Private Use (rcode: %d)", code)
	}
	if code >= 4096 && code <= 65534 {
		return fmt.Sprintf("Unassigned (rcode: %d)", code)
	}
	if code == 65535 {
		return fmt.Sprintf("Reserved, can be allocated by Standards Action (rcode: %d)", code)
	}
	return fmt.Sprintf("Unknown (rcode: %d)", code)
}

// RcodeError indicates a valid DoH API DNS error response.
type RcodeError struct {
	Code     int
	Response JSONOutput
}

func (e RcodeError) Error() string {
	return formatRcodeError(e.Code)
}

func Whois(domain string) (string, error) {
	client := whois.NewClient()
	client.SetTimeout(5 * time.Second)

	result, err := client.Whois(domain)
	if err != nil {
		return "", err
	}
	return whoisOrganization(result)
}

func whoisOrganization(result string) (string, error) {
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
	var rcodeErr RcodeError
	if !errors.As(err, &rcodeErr) {
		jsonBytes, _ := json.MarshalIndent(struct {
			Error string `json:"error"`
		}{Error: err.Error()}, "", "  ")
		fmt.Println(string(jsonBytes))
		return
	}
	output := rcodeErr.Response
	if output.StatusName == "" {
		output.Status = rcodeErr.Code
		output.StatusName = rcodeName(rcodeErr.Code)
	}
	output.Error = err.Error()
	jsonBytes, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(jsonBytes))
}

// outputJSON prints DNS records in JSON format
func outputJSON(output JSONOutput) error {
	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal error: %w", err)
	}
	fmt.Println(string(jsonBytes))
	return nil
}

func makeDNSRecord(r dohRecord, enableWhois bool) DNSRecord {
	record := DNSRecord{
		Name:     r.Name,
		Type:     r.Type,
		TypeName: dnsTypeName(r.Type),
		TTL:      r.TTL,
		Data:     r.Data,
	}
	if enableWhois && ipRecordTypes[r.Type] {
		if whoisResult, err := Whois(r.Data); err == nil && whoisResult != "" {
			record.Whois = whoisResult
		}
	}
	return record
}

func makeDNSRecords(records []dohRecord, enableWhois bool) []DNSRecord {
	if len(records) == 0 {
		return nil
	}
	result := make([]DNSRecord, 0, len(records))
	for _, record := range records {
		result = append(result, makeDNSRecord(record, enableWhois))
	}
	return result
}

func makeJSONOutput(res dohResponse, enableWhois bool) JSONOutput {
	questions := make([]DNSQuestion, 0, len(res.Question))
	for _, question := range res.Question {
		questions = append(questions, DNSQuestion{
			Name:     question.Name,
			Type:     question.Type,
			TypeName: dnsTypeName(question.Type),
		})
	}

	return JSONOutput{
		Status:     res.Status,
		StatusName: rcodeName(res.Status),
		Flags: DNSFlags{
			Truncated:          res.Tc,
			RecursionDesired:   res.Rd,
			RecursionAvailable: res.Ra,
			AuthenticData:      res.Ad,
			CheckingDisabled:   res.Cd,
		},
		Question:   questions,
		Records:    makeDNSRecords(res.Answer, enableWhois),
		Authority:  makeDNSRecords(res.Authority, false),
		Additional: makeDNSRecords(res.Additional, false),
		Comments:   []string(res.Comment),
	}
}

func rcodeName(code int) string {
	if entries := rcodeByCode[code]; len(entries) != 0 {
		return strings.ToUpper(entries[0].name)
	}
	return "UNKNOWN"
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

	output := makeJSONOutput(res, enableWhois)
	if res.Status != 0 {
		return RcodeError{Code: res.Status, Response: output}
	}

	if enableJSON {
		return outputJSON(output)
	}
	return outputText(output)
}

// OutputTextResponse prints a parsed DNS response in human-readable form.
func OutputTextResponse(output JSONOutput) error {
	return outputText(output)
}

func outputText(output JSONOutput) error {
	green := color.New(color.FgGreen).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()

	hasOtherSections := len(output.Authority) > 0 || len(output.Additional) > 0 || len(output.Comments) > 0
	if len(output.Records) == 0 {
		fmt.Println("No answer records")
	} else if hasOtherSections {
		fmt.Println(blue("answer:"))
	}
	printRecords(output.Records, blue, green)

	if len(output.Authority) > 0 {
		fmt.Println(blue("authority:"))
		printRecords(output.Authority, blue, green)
	}
	if len(output.Additional) > 0 {
		fmt.Println(blue("additional:"))
		printRecords(output.Additional, blue, green)
	}
	for _, comment := range output.Comments {
		fmt.Printf("%s: %v\n", blue("comment"), green(comment))
	}
	return nil
}

func printRecords(records []DNSRecord, blue, green func(a ...interface{}) string) {
	for _, r := range records {
		fmt.Printf("%s: %v\n", blue("name"), green(r.Name))
		fmt.Printf("%s: %v\n", blue("type"), green(fmt.Sprintf("%d (%s)", r.Type, r.TypeName)))
		fmt.Printf("%s: %v\n", blue("ttl"), green(r.TTL))
		fmt.Printf("%s: %v\n", blue("data"), green(r.Data))
		if r.Whois != "" {
			fmt.Printf("%s: %v\n", blue("whois"), green(r.Whois))
		}
	}
}
