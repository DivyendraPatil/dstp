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

// NotApplicable marks a check as skipped with an explanatory message (e.g. UDP on a CDN edge).
func NotApplicable(msg string) ResultPart {
	return ResultPart{Content: msg, Status: StatusSkipped}
}

// Result aggregates connectivity checks in a map keyed by PartOrder JSON keys.
// Output order and known keys come from PartOrder — do not add per-check fields.
type Result struct {
	Mu      sync.Mutex            `json:"-"`
	byKey   map[string]ResultPart `json:"-"`
	Network any                   `json:"-"`
}

func (r *Result) ensure() {
	if r.byKey == nil {
		r.byKey = make(map[string]ResultPart, len(PartOrder))
	}
}

// Store sets the outcome for a PartOrder key (e.g. KeyPing).
func (r *Result) Store(key string, part ResultPart) {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	r.ensure()
	r.byKey[key] = part
}

// Get returns the stored part for key, or a zero ResultPart.
func (r *Result) Get(key string) ResultPart {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	if r.byKey == nil {
		return ResultPart{}
	}
	return r.byKey[key]
}

// StoreNetwork sets the optional structured network object for JSON output.
func (r *Result) StoreNetwork(v any) {
	r.Mu.Lock()
	r.Network = v
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
	r.Mu.Lock()
	defer r.Mu.Unlock()
	out := make([]namedPart, 0, len(PartOrder))
	for _, spec := range PartOrder {
		var part ResultPart
		if r.byKey != nil {
			part = r.byKey[spec.Key]
		}
		out = append(out, namedPart{name: spec.Name, key: spec.Key, part: part})
	}
	return out
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
			// Omit skipped/n/a from plaintext to keep profile output tight (still in JSON).
			continue
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
	out := map[string]any{}
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
	r.Mu.Lock()
	netObj := r.Network
	r.Mu.Unlock()
	if netObj != nil {
		out["network"] = netObj
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
