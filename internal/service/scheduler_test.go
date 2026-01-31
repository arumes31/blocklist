package service

import (
	"testing"
)

func TestSchedulerService_CleanOldIPs_Nil(t *testing.T) {
	svc := NewSchedulerService(nil)
	svc.CleanOldIPs("ips")
}

func TestSchedulerService_UpdateAutomateCache_Nil(t *testing.T) {
	svc := NewSchedulerService(nil)
	svc.UpdateAutomateCache()
}
