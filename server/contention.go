package server

import (
	"net"
	"sync"
	"time"
)

type ContentionCache struct {
	mu sync.Mutex
	m  map[string]ContentionCountdown
}

type ContentionCountdown struct {
	countdown       *time.Timer
	ip              net.IP
	protectDeadline time.Time
}

func NewContentionCache() *ContentionCache {
	return &ContentionCache{
		m: make(map[string]ContentionCountdown),
	}
}

// Check return if the IP should be allowed for the key.
func (c *ContentionCache) Check(key string, protectTime time.Duration, ip net.IP) (accept bool, conflictIP net.IP) {
	// Do not limit the different IPs.
	return true, nil
}
