// SPDX-License-Identifier: Apache-2.0

package server

import "testing"

// The dashboard's update notice compares Docker Hub's newest vX.Y.Z tag against
// the running build's VERSION stamp. A fork stamp carries a suffix
// ("v2.65.1-secfix"), and parsing "1-secfix" as 0 made the UI advertise an
// update to the release already running.
func TestSemverPartsIgnoresBuildSuffixes(t *testing.T) {
	cases := []struct {
		in   string
		want [3]int
	}{
		{"v2.65.1", [3]int{2, 65, 1}},
		{"2.65.1", [3]int{2, 65, 1}},
		{"v2.65.1-secfix", [3]int{2, 65, 1}},
		{"v2.65.1+custom", [3]int{2, 65, 1}},
		{"v2.65.1-rc1", [3]int{2, 65, 1}},
		{"V2.65.1", [3]int{2, 65, 1}},
		{" v2.65.1 ", [3]int{2, 65, 1}},
		{"dev", [3]int{0, 0, 0}},
		{"", [3]int{0, 0, 0}},
		{"v2.66", [3]int{2, 66, 0}},
	}
	for _, c := range cases {
		if got := semverParts(c.in); got != c.want {
			t.Errorf("semverParts(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSemverGTWithForkStamp(t *testing.T) {
	// The running fork build IS v2.65.1, so upstream 2.65.1 is not an update.
	if semverGT("2.65.1", "v2.65.1-secfix") {
		t.Fatal("a fork stamp must not read as an older release than its own upstream version")
	}
	// A genuinely newer upstream release still reports.
	if !semverGT("v2.66.0", "v2.65.1-secfix") {
		t.Fatal("a newer upstream release must still be offered")
	}
	// And an older one does not.
	if semverGT("v2.64.9", "v2.65.1-secfix") {
		t.Fatal("an older release must not be offered")
	}
}
