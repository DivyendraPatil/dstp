package common

import (
	"fmt"

	"github.com/fatih/color"
)

var noColor bool

// SetNoColor toggles ANSI color output.
func SetNoColor(v bool) {
	noColor = v
	color.NoColor = v
}

var (
	Yellow  = sprint(color.FgYellow)
	Red     = sprint(color.FgRed)
	Green   = sprint(color.FgGreen)
	Blue    = sprint(color.FgBlue)
	Magenta = sprint(color.FgMagenta)
	Cyan    = sprint(color.FgCyan)
	White   = sprint(color.FgHiWhite)
)

func sprint(attr color.Attribute) func(a ...interface{}) string {
	colored := color.New(attr).SprintFunc()
	return func(a ...interface{}) string {
		if noColor {
			return fmt.Sprint(a...)
		}
		return colored(a...)
	}
}
