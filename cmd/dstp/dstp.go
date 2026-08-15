package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	flag "github.com/spf13/pflag"

	"github.com/ycd/dstp/config"
	"github.com/ycd/dstp/pkg/dstp"
)

func main() {
	fs := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ExitOnError)

	opts, err := config.ConfigureOptions(fs, os.Args[1:])
	if err != nil {
		config.UsageAndExit(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err = dstp.RunAllTests(ctx, *opts)
	if err != nil {
		if errors.Is(err, dstp.ErrChecksFailed) {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
