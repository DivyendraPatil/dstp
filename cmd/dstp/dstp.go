package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	flag "github.com/spf13/pflag"

	"github.com/DivyendraPatil/dstp/config"
	"github.com/DivyendraPatil/dstp/pkg/dstp"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ContinueOnError)
	fs.SetOutput(stderr)

	opts, err := config.ConfigureOptions(fs, args)
	if err != nil {
		switch {
		case errors.Is(err, config.ErrHelp):
			config.PrintUsage(stdout)
			return 0
		case errors.Is(err, config.ErrVersion):
			config.PrintVersion(stdout)
			return 0
		case errors.Is(err, config.ErrUsage):
			config.UsageError(stderr, err)
			return 2
		default:
			config.UsageError(stderr, err)
			return 2
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err = dstp.RunAllTests(ctx, *opts)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "interrupted")
			return 130
		}
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintln(stderr, "deadline exceeded")
			return 1
		}
		if errors.Is(err, dstp.ErrChecksFailed) {
			return 1
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
