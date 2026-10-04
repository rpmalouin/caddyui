// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
)

// Review finding #12 (2026-10-04): the upstream tester accepts a caller-chosen
// host, so link-local targets (cloud metadata at 169.254.169.254, IPv6
// link-local) must be refused before any request goes out.
func TestForbidLinkLocalTarget(t *testing.T) {
	blocked := []string{
		"169.254.169.254", // cloud metadata
		"169.254.0.1",
		"fe80::1",
		"ff02::1",
	}
	for _, host := range blocked {
		if err := forbidLinkLocalTarget(host); err == nil {
			t.Errorf("forbidLinkLocalTarget(%q) = nil, want a refusal", host)
		} else if !strings.Contains(err.Error(), "link-local") {
			t.Errorf("forbidLinkLocalTarget(%q) error = %v, want it to mention link-local", host, err)
		}
	}

	allowed := []string{
		"127.0.0.1",
		"10.0.0.5",
		"192.168.1.20",
		"::1",
		"2001:db8::1",
	}
	for _, host := range allowed {
		if err := forbidLinkLocalTarget(host); err != nil {
			t.Errorf("forbidLinkLocalTarget(%q) = %v, want nil", host, err)
		}
	}

	// A hostname that does not resolve must not fail here: the probe itself
	// reports the DNS failure with its actionable hint.
	if err := forbidLinkLocalTarget("this-name-does-not-resolve.invalid"); err != nil {
		t.Errorf("unresolvable host = %v, want nil (probe reports the DNS failure)", err)
	}
}
