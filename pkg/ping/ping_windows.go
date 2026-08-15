//go:build windows

package ping

import (
	probing "github.com/prometheus-community/pro-bing"
)

func createPinger(addr string) (*probing.Pinger, error) {
	p, err := probing.NewPinger(addr)
	if err != nil {
		return nil, err
	}

	// https://pkg.go.dev/github.com/prometheus-community/pro-bing#readme-windows
	p.SetPrivileged(true)

	return p, nil
}
