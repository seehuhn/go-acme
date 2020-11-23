package cert

import (
	"strings"
	"testing"
)

func TestStringSliceLess(t *testing.T) {
	cases := []*struct {
		a, b string
		res  bool
	}{
		{"", "a", true},
		{"a,b", "a,b,d", true},
		{"a,b,c", "a,b,d", true},
		{"a,b,d", "a,b,d", false},
		{"a,b,d,x", "a,b,d", false},
		{"a,b,e", "a,b,d", false},
		{"a,b,e", "", false},
		{"", "", false},
	}
	for i, test := range cases {
		a := strings.Split(test.a, ",")
		b := strings.Split(test.b, ",")
		got := stringSliceLess(a, b)
		if got != test.res {
			t.Errorf("test %d failed: got %t, expected %t",
				i, got, test.res)
		}
	}
}
