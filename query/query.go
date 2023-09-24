package query

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/fatih/color"
	"github.com/likexian/whois"
)

type dohRespose struct {
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

var dohURL = "https://cloudflare-dns.com/dns-query"

func Whois(domain string) (string, error) {
	result, err := whois.Whois(domain)
	if err != nil {
		return "", err
	}
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "OrgName:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "OrgName:")), nil
		}
	}
	return "", fmt.Errorf("OrgName not found in WHOIS lookup result")
}

func Do(queryType string, domain string) {
	url := fmt.Sprintf("%s?name=%s&type=%s", dohURL, domain, queryType)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("new request error: %v\n", err)
		return
	}

	req.Header.Set("accept", "application/dns-json")

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("request do error: %v\n", err)
		return
	}
	defer response.Body.Close()

	content, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("read body error: %v\n", err)
		return
	}

	if response.StatusCode != http.StatusOK {
		fmt.Println("Error response status:", response.Status)
		fmt.Println("Error text:", string(content))
		return
	}

	var res dohRespose
	if err := json.Unmarshal(content, &res); err != nil {
		fmt.Printf("unmarshal error: %v\n", err)
		return
	}

	if res.Status != 0 {
		fmt.Println("rcode:", res.Status)
		fmt.Println("You can check rcode here: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6")
		return
	}

	if res.Answer == nil {
		fmt.Println("There is no such DNS record")
		return
	}

	green := color.New(color.FgGreen).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()
	for _, r := range res.Answer {
		fmt.Printf("%s: %v\n", blue("name"), green(r.Name))
		fmt.Printf("%s: %v\n", blue("type"), green(r.Type))
		fmt.Printf("%s: %v\n", blue("ttl"), green(r.TTL))
		fmt.Printf("%s: %v\n", blue("data"), green(r.Data))

		whois, err := Whois(r.Data)
		if err == nil && whois != "" {
			fmt.Printf("%s: %v\n", blue("whois"), green(whois))
		}

		fmt.Println()
	}
}
