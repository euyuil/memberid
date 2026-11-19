package oidcprovider

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDirectLoginQuotaAcrossBrowsers(t *testing.T) {
	var quota directLoginQuota
	var accepted atomic.Int32
	var workers sync.WaitGroup
	now := time.Now()
	for i := range directStartsPerMinute/browserStartsPerMinute + 1 {
		workers.Go(func() {
			for range browserStartsPerMinute {
				if quota.allow(strconv.Itoa(i), now) {
					accepted.Add(1)
				}
			}
		})
	}
	workers.Wait()
	if got := accepted.Load(); got != directStartsPerMinute {
		t.Fatalf("accepted %d direct login starts, want %d", got, directStartsPerMinute)
	}
	if quota.allow("new browser", now.Add(time.Minute-time.Nanosecond)) || !quota.allow("new browser", now.Add(time.Minute)) {
		t.Fatal("the process quota must reopen at the next window")
	}
}
