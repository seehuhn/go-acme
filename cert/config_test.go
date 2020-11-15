// seehuhn.de/go/acme/cert - renew and manage server certificates
// Copyright (C) 2020  Jochen Voss
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
	"reflect"
	"testing"
)

func TestCertificateDomains(t *testing.T) {
	config := &Config{
		Sites: []*ConfigSite{
			{
				Domain:   "a.example.com",
				UseKeyOf: "b.example.com",
			},
			{
				Domain: "b.example.com",
			},
			{
				Domain:   "c.example.com",
				UseKeyOf: "b.example.com",
			},
			{
				Domain: "d.example.com",
			},
		},
	}

	lists, err := config.CertDomains()
	if err != nil {
		t.Fatal(err)
	}

	expected := [][]string{
		{"b.example.com", "a.example.com", "c.example.com"},
		{"d.example.com"},
	}
	if !reflect.DeepEqual(lists, expected) {
		t.Errorf("wrong result: %v", lists)
	}

	config.Sites[2].UseKeyOf = "d.examples.com"
	_, err = config.CertDomains()
	if err == nil {
		t.Error("failed to detect chain of length 2")
	}
	config.Sites[2].UseKeyOf = ""

	config.Sites[0].UseKeyOf = "misspelled.examples.com"
	_, err = config.CertDomains()
	if err == nil {
		t.Error("failed to detect mis-spelled domain name")
	}
}
