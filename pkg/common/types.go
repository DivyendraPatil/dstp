// Package common holds shared result types and terminal helpers for dstp.
package common

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/mattn/go-isatty"
)

// Address is a hostname or IP under test.
type Address string

func (a Address) String() string { return string(a) }

// ResultPart is one check outcome.
type ResultPart struct {
	Content string `json:"content,omitempty"`
	Error   error  `json:"-"`
	Status  string `json:"status"` // ok | error | skipped
}

func (o ResultPart) String() string {
	if o.Error != nil {
		return Red(o.Error.Error())
	}
	return o.Content
}

func (o ResultPart) message() string {
	if o.Error != nil {
		return o.Error.Error()
	}
	return o.Content
}

// OK is a successful check result.
func OK(content string) ResultPart { return ResultPart{Content: content, Status: "ok"} }

// Fail is a failed check result.
func Fail(err error) ResultPart { return ResultPart{Error: err, Status: "error"} }

// Skipped marks a check that was not run.
func Skipped() ResultPart { return ResultPart{Content: "skipped", Status: "skipped"} }

// Result aggregates all connectivity checks.
type Result struct {
	Ping      ResultPart `json:"ping"`
	DNS       ResultPart `json:"dns"`            // default resolver (or DoH)
	SystemDNS ResultPart `json:"system_dns"`     // configured resolver (--dns)
	Records   ResultPart `json:"records"`        // A/AAAA/CNAME/MX/NS/TXT
	TCP       ResultPart `json:"tcp"`
	TLS       ResultPart `json:"tls"`
	HTTPS     ResultPart `json:"https"`
	Mu        sync.Mutex `json:"-"`
}

// Store writes a part under the result mutex.
func (r *Result) Store(dst *ResultPart, part ResultPart) {
	r.Mu.Lock()
	*dst = part
	r.Mu.Unlock()
}

// Failed reports whether any executed check failed.
func (r *Result) Failed() bool {
	for _, p := range r.parts() {
		if p.part.Status == "error" || p.part.Error != nil {
			return true
		}
	}
	return false
}

type namedPart struct {
	name string
	key  string
	part ResultPart
}

func (r *Result) parts() []namedPart {
	return []namedPart{
		{"Ping", "ping", r.Ping},
		{"DNS", "dns", r.DNS},
		{"ConfiguredDNS", "system_dns", r.SystemDNS},
		{"Records", "records", r.Records},
		{"TCP", "tcp", r.TCP},
		{"TLS", "tls", r.TLS},
		{"HTTPS", "https", r.HTTPS},
	}
}

// Output renders plaintext or JSON.
func (r *Result) Output(outputType string) string {
	if outputType == "json" {
		return r.jsonOutput()
	}
	return r.plaintextOutput()
}

func (r *Result) plaintextOutput() string {
	var output string
	for _, p := range r.parts() {
		if p.part.Status == "" && p.part.Content == "" && p.part.Error == nil {
			continue
		}
		switch {
		case p.part.Error != nil || p.part.Status == "error":
			output += fmt.Sprintf("%s: %s\n", White(p.name), Red(p.part.message()))
		case p.part.Status == "skipped":
			output += fmt.Sprintf("%s: %s\n", White(p.name), p.part.Content)
		default:
			output += fmt.Sprintf("%s: %s\n", White(p.name), Green(p.part.Content))
		}
	}
	return output
}

func (r *Result) jsonOutput() string {
	type item struct {
		Status  string `json:"status"`
		Content string `json:"content,omitempty"`
		Error   string `json:"error,omitempty"`
	}
	out := map[string]item{}
	for _, p := range r.parts() {
		if p.part.Status == "" && p.part.Content == "" && p.part.Error == nil {
			continue
		}
		it := item{Status: p.part.Status}
		if it.Status == "" {
			if p.part.Error != nil {
				it.Status = "error"
			} else {
				it.Status = "ok"
			}
		}
		if p.part.Error != nil {
			it.Error = p.part.Error.Error()
		} else if p.part.Content != "" {
			it.Content = p.part.Content
		}
		out[p.key] = it
	}
	byt, _ := json.MarshalIndent(out, "", "  ")
	return string(byt)
}

// InitColor disables ANSI colors when stdout is not a TTY or NO_COLOR is set.
func InitColor() {
	if os.Getenv("NO_COLOR") != "" || !isatty.IsTerminal(os.Stdout.Fd()) {
		SetNoColor(true)
	}
}
