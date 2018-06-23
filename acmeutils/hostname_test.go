package acmeutils

import "testing"

func TestHostname(t *testing.T) {
	type entry struct {
		Input, Output string
		Valid         bool
	}

	var entries = []entry{
		{"example.com", "example.com", true},
		{"example.com.", "example.com", true},
		{"example.com..", "", false},
		{"ex ample.com.", "", false},
		{"む.com", "xn--dbk.com", true},
		{"む..com.", "", false},
		{"*.example.com", "*.example.com", true},
		{"*.*.example.com", "", false},
		{"foo.*.example.com", "", false},
	}

	for _, e := range entries {
		out, err := NormalizeHostname(e.Input)
		if e.Valid != (err == nil) {
			t.Logf("hostname fail: expected valid=%v, got err=%v", e.Valid, err)
			t.Fail()
		}

		if out != e.Output {
			t.Logf("hostname fail: for input %q, %q != %q", e.Input, out, e.Output)
			t.Fail()
		}
	}
}
