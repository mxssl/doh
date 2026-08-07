package query

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type errorReadCloser struct{}

func (errorReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func (errorReadCloser) Close() error {
	return nil
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close write pipe: %v", err)
	}
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read captured stdout: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("failed to close read pipe: %v", err)
	}
	return buf.String()
}

func TestFormatRcodeErrorKnownCode(t *testing.T) {
	got := formatRcodeError(3)
	want := "NXDomain: Non-Existent Domain (rcode: 3)"

	if got != want {
		t.Fatalf("unexpected format for known rcode; got %q, want %q", got, want)
	}
}

func TestFormatRcodeErrorReservedRange(t *testing.T) {
	got := formatRcodeError(3841)
	want := "Reserved for Private Use (rcode: 3841)"

	if got != want {
		t.Fatalf("unexpected format for reserved rcode; got %q, want %q", got, want)
	}
}

func TestFormatRcodeErrorUnknown(t *testing.T) {
	got := formatRcodeError(-1)
	want := "Unknown (rcode: -1)"

	if got != want {
		t.Fatalf("unexpected format for unknown rcode; got %q, want %q", got, want)
	}
}

func TestFormatRcodeErrorSpecialCases(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{code: 9, want: "NotAuth: Server Not Authoritative for zone | NotAuth: Not Authorized (rcode: 9)"},
		{code: 12, want: "Unassigned (rcode: 12)"},
		{code: 24, want: "Unassigned (rcode: 24)"},
		{code: 4096, want: "Unassigned (rcode: 4096)"},
		{code: 65535, want: "Reserved, can be allocated by Standards Action (rcode: 65535)"},
	}

	for _, tt := range tests {
		got := formatRcodeError(tt.code)
		if got != tt.want {
			t.Fatalf("unexpected output for rcode %d; got %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestValidProvidersContainsDefaults(t *testing.T) {
	providers := ValidProviders()

	if !slices.Contains(providers, "cloudflare") {
		t.Fatalf("expected providers to include cloudflare, got %v", providers)
	}
	if !slices.Contains(providers, "google") {
		t.Fatalf("expected providers to include google, got %v", providers)
	}
}

func TestGetProviderURLUnknown(t *testing.T) {
	_, err := GetProviderURL("unknown")
	if err == nil {
		t.Fatalf("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "unknown provider: unknown") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRcodeErrorImplementsError(t *testing.T) {
	err := error(RcodeError{Code: 3})
	var rcodeErr RcodeError

	if !errors.As(err, &rcodeErr) {
		t.Fatalf("expected errors.As to match RcodeError")
	}
	if rcodeErr.Code != 3 {
		t.Fatalf("unexpected rcode value; got %d, want %d", rcodeErr.Code, 3)
	}
}

func TestOutputJSONErrorForRcodeError(t *testing.T) {
	out := captureStdout(t, func() {
		OutputJSONError(RcodeError{Code: 3})
	})

	if !strings.Contains(out, `"error": "NXDomain: Non-Existent Domain (rcode: 3)"`) {
		t.Fatalf("json output missing expected error message: %s", out)
	}
	if strings.Contains(out, `"error_code"`) {
		t.Fatalf("json output must not contain error_code field: %s", out)
	}
	if !strings.Contains(out, `"status": 3`) || !strings.Contains(out, `"status_name": "NXDOMAIN"`) {
		t.Fatalf("json output missing DNS response status: %s", out)
	}
}

func TestOutputJSONErrorForTransportError(t *testing.T) {
	out := captureStdout(t, func() {
		OutputJSONError(errors.New("transport failed"))
	})

	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("expected valid json, got %q: %v", out, err)
	}
	if got["error"] != "transport failed" || len(got) != 1 {
		t.Fatalf("unexpected error output: %v", got)
	}
}

func addTestProvider(t *testing.T, url string) string {
	t.Helper()

	const providerName = "test-provider"
	oldURL, existed := providerURLs[providerName]
	providerURLs[providerName] = url

	t.Cleanup(func() {
		if existed {
			providerURLs[providerName] = oldURL
			return
		}
		delete(providerURLs, providerName)
	})

	return providerName
}

func TestDoReturnsRcodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":3}`))
	}))
	defer srv.Close()

	provider := addTestProvider(t, srv.URL)
	err := Do("a", "example.com", false, false, provider)
	if err == nil {
		t.Fatalf("expected rcode error")
	}

	var rcodeErr RcodeError
	if !errors.As(err, &rcodeErr) {
		t.Fatalf("expected RcodeError, got: %v", err)
	}
	if rcodeErr.Code != 3 {
		t.Fatalf("unexpected rcode value; got %d, want %d", rcodeErr.Code, 3)
	}
	if rcodeErr.Response.Status != 3 || rcodeErr.Response.StatusName != "NXDOMAIN" {
		t.Fatalf("unexpected response on rcode error: %+v", rcodeErr.Response)
	}
}

func TestDoBuildsProviderRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Query().Get("name"), "example.com"; got != want {
			t.Errorf("unexpected query name; got %q, want %q", got, want)
		}
		if got, want := r.URL.Query().Get("type"), "HTTPS"; got != want {
			t.Errorf("unexpected query type; got %q, want %q", got, want)
		}
		if got, want := r.Header.Get("Accept"), "application/dns-json"; got != want {
			t.Errorf("unexpected Accept header; got %q, want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0}`))
	}))
	defer srv.Close()

	provider := addTestProvider(t, srv.URL)
	_ = captureStdout(t, func() {
		if err := Do("HTTPS", "example.com", false, false, provider); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})
}

func TestDoRequestError(t *testing.T) {
	oldClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection failed")
	})}
	t.Cleanup(func() { http.DefaultClient = oldClient })

	err := Do("A", "example.com", false, false, DefaultProvider)
	if err == nil || !strings.Contains(err.Error(), "request do error") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDoReadBodyError(t *testing.T) {
	oldClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       errorReadCloser{},
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() { http.DefaultClient = oldClient })

	err := Do("A", "example.com", false, false, DefaultProvider)
	if err == nil || !strings.Contains(err.Error(), "read body error") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDoNon200Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream failure"))
	}))
	defer srv.Close()

	provider := addTestProvider(t, srv.URL)
	err := Do("a", "example.com", false, false, provider)
	if err == nil {
		t.Fatalf("expected non-200 error")
	}
	if !strings.Contains(err.Error(), "error response status") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestDoInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{`))
	}))
	defer srv.Close()

	provider := addTestProvider(t, srv.URL)
	err := Do("a", "example.com", false, false, provider)
	if err == nil {
		t.Fatalf("expected unmarshal error")
	}
	if !strings.Contains(err.Error(), "unmarshal error") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestDoNewRequestError(t *testing.T) {
	provider := addTestProvider(t, "://bad-url")
	err := Do("a", "example.com", false, false, provider)
	if err == nil {
		t.Fatalf("expected new request error")
	}
	if !strings.Contains(err.Error(), "new request error") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestDoNoAnswerTextOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0}`))
	}))
	defer srv.Close()

	provider := addTestProvider(t, srv.URL)
	out := captureStdout(t, func() {
		err := Do("a", "example.com", false, false, provider)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	if !strings.Contains(out, "No answer records") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestDoNoAnswerJSONOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0}`))
	}))
	defer srv.Close()

	provider := addTestProvider(t, srv.URL)
	out := captureStdout(t, func() {
		err := Do("a", "example.com", false, true, provider)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	var got JSONOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("expected valid json output, got %q: %v", out, err)
	}
	if len(got.Records) != 0 {
		t.Fatalf("expected empty records, got %v", got.Records)
	}
}

func TestDoSuccessJSONOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"name":"example.com.","type":1,"TTL":120,"data":"93.184.216.34"}]}`))
	}))
	defer srv.Close()

	provider := addTestProvider(t, srv.URL)
	out := captureStdout(t, func() {
		err := Do("a", "example.com", false, true, provider)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	var got JSONOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("expected valid json output, got %q: %v", out, err)
	}
	if len(got.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(got.Records))
	}
	rec := got.Records[0]
	if rec.Name != "example.com." || rec.Type != 1 || rec.TTL != 120 || rec.Data != "93.184.216.34" {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if rec.TypeName != "A" {
		t.Fatalf("unexpected record type name; got %q, want A", rec.TypeName)
	}
}

func TestDoSuccessTextOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"name":"example.com.","type":1,"TTL":120,"data":"93.184.216.34"}]}`))
	}))
	defer srv.Close()

	provider := addTestProvider(t, srv.URL)
	out := captureStdout(t, func() {
		err := Do("a", "example.com", false, false, provider)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	if !strings.Contains(out, "name: example.com.") {
		t.Fatalf("missing record name in output: %s", out)
	}
	if !strings.Contains(out, "type: 1 (A)") {
		t.Fatalf("missing record type in output: %s", out)
	}
	if !strings.Contains(out, "ttl: 120") {
		t.Fatalf("missing record ttl in output: %s", out)
	}
	if !strings.Contains(out, "data: 93.184.216.34") {
		t.Fatalf("missing record data in output: %s", out)
	}
}

func TestDoOutputsAllResponseSections(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{
			"Status": 0,
			"TC": false,
			"RD": true,
			"RA": true,
			"AD": true,
			"CD": false,
			"Question": [{"name":"example.com.","type":15}],
			"Answer": [{"name":"example.com.","type":15,"TTL":300,"data":"10 mail.example.com."}],
			"Authority": [{"name":"example.com.","type":6,"TTL":600,"data":"ns.example.com. hostmaster.example.com. 1 2 3 4 5"}],
			"Additional": [{"name":"mail.example.com.","type":1,"TTL":300,"data":"192.0.2.10"}],
			"Comment": ["cached response"]
		}`))
	}))
	defer srv.Close()

	provider := addTestProvider(t, srv.URL)
	out := captureStdout(t, func() {
		if err := Do("mx", "example.com", false, true, provider); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	var got JSONOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("expected valid json, got %q: %v", out, err)
	}
	if got.Status != 0 || got.StatusName != "NOERROR" {
		t.Fatalf("unexpected response status: %d (%s)", got.Status, got.StatusName)
	}
	if !got.Flags.RecursionDesired || !got.Flags.RecursionAvailable || !got.Flags.AuthenticData {
		t.Fatalf("unexpected response flags: %+v", got.Flags)
	}
	if len(got.Question) != 1 || got.Question[0].TypeName != "MX" {
		t.Fatalf("unexpected question section: %+v", got.Question)
	}
	if len(got.Records) != 1 || got.Records[0].TypeName != "MX" {
		t.Fatalf("unexpected answer section: %+v", got.Records)
	}
	if len(got.Authority) != 1 || got.Authority[0].TypeName != "SOA" {
		t.Fatalf("unexpected authority section: %+v", got.Authority)
	}
	if len(got.Additional) != 1 || got.Additional[0].TypeName != "A" {
		t.Fatalf("unexpected additional section: %+v", got.Additional)
	}
	if len(got.Comments) != 1 || got.Comments[0] != "cached response" {
		t.Fatalf("unexpected comments: %+v", got.Comments)
	}
}

func TestResponseCommentAcceptsStringAndArray(t *testing.T) {
	for _, input := range []string{`"diagnostic"`, `["diagnostic"]`} {
		var got responseComment
		if err := json.Unmarshal([]byte(input), &got); err != nil {
			t.Fatalf("failed to unmarshal %s: %v", input, err)
		}
		if len(got) != 1 || got[0] != "diagnostic" {
			t.Fatalf("unexpected comment for %s: %+v", input, got)
		}
	}
}

func TestResponseCommentHandlesEmptyAndInvalidValues(t *testing.T) {
	var empty responseComment
	if err := json.Unmarshal([]byte(`""`), &empty); err != nil {
		t.Fatalf("failed to unmarshal empty comment: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected no comments, got %+v", empty)
	}

	var invalid responseComment
	if err := json.Unmarshal([]byte(`{"message":"bad"}`), &invalid); err == nil {
		t.Fatal("expected invalid comment shape to fail")
	}
}

func TestOutputTextResponseIncludesAllSections(t *testing.T) {
	output := JSONOutput{
		Records:    []DNSRecord{{Name: "example.com.", Type: 15, TypeName: "MX", TTL: 300, Data: "10 mail.example.com."}},
		Authority:  []DNSRecord{{Name: "example.com.", Type: 6, TypeName: "SOA", TTL: 600, Data: "ns.example.com. hostmaster.example.com. 1 2 3 4 5"}},
		Additional: []DNSRecord{{Name: "mail.example.com.", Type: 1, TypeName: "A", TTL: 300, Data: "192.0.2.10", Whois: "Example Org"}},
		Comments:   []string{"cached response"},
	}

	out := captureStdout(t, func() {
		if err := OutputTextResponse(output); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})
	for _, expected := range []string{
		"answer:", "type: 15 (MX)", "authority:", "type: 6 (SOA)",
		"additional:", "type: 1 (A)", "whois: Example Org", "comment: cached response",
	} {
		if !strings.Contains(out, expected) {
			t.Fatalf("output missing %q: %s", expected, out)
		}
	}
}

func TestWhoisOrganization(t *testing.T) {
	tests := []struct {
		name   string
		result string
		want   string
	}{
		{name: "ARIN", result: "NetRange: 192.0.2.0 - 192.0.2.255\nOrgName: Example Org\n", want: "Example Org"},
		{name: "RIPE", result: "inetnum: 192.0.2.0/24\norg-name: Example Europe\n", want: "Example Europe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := whoisOrganization(tt.result)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected organization; got %q, want %q", got, tt.want)
			}
		})
	}

	if _, err := whoisOrganization("no organization here"); err == nil {
		t.Fatal("expected missing organization error")
	}
}

func TestRcodeNameUnknown(t *testing.T) {
	if got, want := rcodeName(65400), "UNKNOWN"; got != want {
		t.Fatalf("unexpected rcode name; got %q, want %q", got, want)
	}
}

func TestUnknownTypeNameUsesGenericNotation(t *testing.T) {
	if got, want := dnsTypeName(65400), "TYPE65400"; got != want {
		t.Fatalf("unexpected unknown type name; got %q, want %q", got, want)
	}
}
