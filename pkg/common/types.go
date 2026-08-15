package common

import (
	"encoding/json"
	"fmt"
	"sync"
)

type Args []string

type Address string

type ResultPart struct {
	Content string
	Error   error
}

func (o ResultPart) String() string {
	if o.Error != nil {
		return Red(o.Error.Error())
	}

	return o.Content
}

// value returns Content on success, or the error string on failure.
func (o ResultPart) value() string {
	if o.Error != nil {
		return o.Error.Error()
	}
	return o.Content
}

func (a Address) String() string {
	return string(a)
}

type Result struct {
	Ping ResultPart `json:"ping"`
	// DNS is resolution via the default system resolver.
	DNS ResultPart `json:"dns"`
	// SystemDNS is resolution via the configured resolver (system or --dns).
	// Plaintext output labels this ConfiguredDNS.
	SystemDNS ResultPart `json:"system_dns"`
	TLS       ResultPart `json:"tls"`
	HTTPS     ResultPart `json:"https"`

	Mu sync.Mutex `json:"-"`
}

func (r *Result) Output(outputType string) string {
	var output string

	switch outputType {
	case "plaintext":
		parts := []struct {
			name string
			part ResultPart
		}{
			{"Ping", r.Ping},
			{"DNS", r.DNS},
			{"ConfiguredDNS", r.SystemDNS},
			{"TLS", r.TLS},
			{"HTTPS", r.HTTPS},
		}
		for _, p := range parts {
			if p.part.Error != nil {
				output += fmt.Sprintf("%s: %v\n", White(p.name), p.part)
			} else {
				output += fmt.Sprintf("%s: %v\n", White(p.name), Green(p.part.Content))
			}
		}
	case "json":
		v := map[string]string{}
		if s := r.Ping.value(); s != "" {
			v["ping"] = s
		}
		if s := r.DNS.value(); s != "" {
			v["dns"] = s
		}
		if s := r.SystemDNS.value(); s != "" {
			v["system_dns"] = s
		}
		if s := r.TLS.value(); s != "" {
			v["tls"] = s
		}
		if s := r.HTTPS.value(); s != "" {
			v["https"] = s
		}

		byt, _ := json.MarshalIndent(v, "", "  ")
		output += string(byt)
	}

	return output
}
