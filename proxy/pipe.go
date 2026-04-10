package proxy

import (
	"io"
	"net"
	"sync"
)

// Pipe bidirectionally copies data between two connections.
// Both connections are closed when either direction completes.
func pipe(a, b net.Conn) {
	var once sync.Once
	closeAll := func() { once.Do(func() { _ = a.Close(); _ = b.Close() }) }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(b, a); closeAll() }() //nolint:errcheck
	go func() { defer wg.Done(); io.Copy(a, b); closeAll() }() //nolint:errcheck
	wg.Wait()
}
