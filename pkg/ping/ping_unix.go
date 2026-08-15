//go:build !windows

package ping

import (
	probing "github.com/prometheus-community/pro-bing"
)

func createPinger(addr string) (*probing.Pinger, error) {
	return probing.NewPinger(addr)
}
