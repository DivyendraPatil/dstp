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
	_, _ = fmt.Fprintf(p.w, "… %s\n", name)
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
			status = common.StatusError
		} else {
			status = common.StatusOK
		}
	}
	glyph := "•"
	switch status {
	case common.StatusOK:
		glyph = "✓"
	case common.StatusWarning:
		glyph = "!"
	case common.StatusInconclusive:
		glyph = "?"
	case common.StatusError:
		glyph = "✗"
	case common.StatusSkipped:
		glyph = "-"
	}
	_, _ = fmt.Fprintf(p.w, "%s %s (%s)\n", glyph, name, status)
}
