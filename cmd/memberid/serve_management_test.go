package main

import "testing"

func TestManagementListenBoundary(t *testing.T) {
	for _, test := range []struct {
		address          string
		private, allowed bool
	}{
		{"127.0.0.1:8081", false, true}, {"[::1]:8081", false, true},
		{"0.0.0.0:8081", false, false}, {"10.0.0.1:8081", false, false},
		{"0.0.0.0:8081", true, true}, {"[::]:8081", true, true}, {"10.0.0.1:8081", true, true},
		{"203.0.113.1:8081", true, false}, {"localhost:8081", false, false}, {":8081", true, false},
	} {
		if err := managementAddress(test.address, test.private); (err == nil) != test.allowed {
			t.Errorf("address %s private=%v: %v", test.address, test.private, err)
		}
	}
}
