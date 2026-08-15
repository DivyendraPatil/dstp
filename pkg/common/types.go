package common

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"unicode"

	"github.com/mattn/go-isatty"
)

// Address is a hostname or IP under test.
type Address string

func (a Address) String() string { return string(a) }

// Status values for a check outcome.
const (
	StatusOK           = "ok"
	StatusWarning      = "warning"
	StatusInconclusive = "inconclusive"
	StatusError        = "error"
	StatusSkipped      = "skipped"
)

// ResultPart is one check outcome.
type ResultPart struct {
	Content string `json:"content,omitempty"`
	Error   error  `json:"-"`
	Status  string `json:"status"` // ok | warning | inconclusive | error | skipped
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

func OK(content string) ResultPart {
	return ResultPart{Content: content, Status: StatusOK}
}

func Warn(content string) ResultPart {
	return ResultPart{Content: content, Status: StatusWarning}
}

func Inconclusive(content string) ResultPart {
	return ResultPart{Content: content, Status: StatusInconclusive}
}

func Fail(err error) ResultPart {
	return ResultPart{Error: err, Status: StatusError}
}

func Skipped() ResultPart {
	return ResultPart{Content: "skipped", Status: StatusSkipped}
}

// Result aggregates all connectivity checks. Field order here drives plaintext output order.
type Result struct {
	Ping       ResultPart `json:"ping"`
	DNS        ResultPart `json:"dns"`
	SystemDNS  ResultPart `json:"configured_dns"`
	Records    ResultPart `json:"records"`
	TCP        ResultPart `json:"tcp"`
	UDP        ResultPart `json:"udp"`
	TLS        ResultPart `json:"tls"`
	HTTP       ResultPart `json:"http"`
	HTTPS      ResultPart `json:"https"`
	Traceroute ResultPart `json:"traceroute"`
	Whois      ResultPart `json:"whois"`
	MTU        ResultPart `json:"mtu"`
	Mu         sync.Mutex `json:"-"`
}

func (r *Result) Store(dst *ResultPart, part ResultPart) {
	r.Mu.Lock()
	*dst = part
	r.Mu.Unlock()
}

func (r *Result) Failed() bool {
	for _, p := range r.parts() {
		if p.part.Status == StatusError || p.part.Error != nil {
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
		{"ConfiguredDNS", "configured_dns", r.SystemDNS},
		{"Records", "records", r.Records},
		{"TCP", "tcp", r.TCP},
		{"UDP", "udp", r.UDP},
		{"TLS", "tls", r.TLS},
		{"HTTP", "http", r.HTTP},
		{"HTTPS", "https", r.HTTPS},
		{"Traceroute", "traceroute", r.Traceroute},
		{"Whois", "whois", r.Whois},
		{"MTU", "mtu", r.MTU},
	}
}

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
		msg := sanitizeForTerminal(p.part.message())
		switch {
		case p.part.Error != nil || p.part.Status == StatusError:
			output += fmt.Sprintf("%s: %s\n", White(p.name), Red(msg))
		case p.part.Status == StatusWarning:
			output += fmt.Sprintf("%s: %s\n", White(p.name), Yellow(msg))
		case p.part.Status == StatusInconclusive:
			output += fmt.Sprintf("%s: %s\n", White(p.name), Cyan(msg))
		case p.part.Status == StatusSkipped:
			output += fmt.Sprintf("%s: %s\n", White(p.name), msg)
		default:
			output += fmt.Sprintf("%s: %s\n", White(p.name), Green(msg))
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
				it.Status = StatusError
			} else {
				it.Status = StatusOK
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

// sanitizeForTerminal strips/escapes control characters for plaintext display.
func sanitizeForTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n':
			b.WriteRune(' ')
		case unicode.IsControl(r):
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func InitColor() {
	if os.Getenv("NO_COLOR") != "" || !isatty.IsTerminal(os.Stdout.Fd()) {
		SetNoColor(true)
	}
}
