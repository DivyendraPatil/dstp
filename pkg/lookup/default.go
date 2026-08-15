package lookup

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ycd/dstp/pkg/common"
)

// Default resolves addr with the system default resolver (ignores --dns).
// This is distinct from Host, which uses the configured resolver (system or --dns).
func Default(ctx context.Context, wg *sync.WaitGroup, addr common.Address, timeout int, result *common.Result) error {
	defer wg.Done()

	lookupCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		lookupCtx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}

	part := common.ResultPart{}
	addrs, err := net.DefaultResolver.LookupHost(lookupCtx, addr.String())
	if err != nil {
		part.Error = err
		result.Mu.Lock()
		result.DNS = part
		result.Mu.Unlock()
		return err
	}

	part.Content = "resolving " + strings.Join(addrs, ", ")
	result.Mu.Lock()
	result.DNS = part
	result.Mu.Unlock()
	return nil
}
