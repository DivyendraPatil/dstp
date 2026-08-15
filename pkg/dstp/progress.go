package dstp

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

// progressWriter prints lightweight start/done lines to stderr.
type progressWriter struct {
	enabled bool
	mu      sync.Mutex
	w       io.Writer
}

func newProgress(enabled bool) *progressWriter {
	return &progressWriter{enabled: enabled, w: os.Stderr}
}

func (p *progressWriter) start(name string) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "… %s\n", name)
}

func (p *progressWriter) done(name string, part common.ResultPart) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	status := part.Status
	if status == "" {
		if part.Error != nil {
			status = "error"
		} else {
			status = "ok"
		}
	}
	fmt.Fprintf(p.w, "✓ %s (%s)\n", name, status)
}
