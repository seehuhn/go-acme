// seehuhn.de/go/acme - renew and manage server certificates
// Copyright (C) 2024  Jochen Voss <voss@seehuhn.de>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
