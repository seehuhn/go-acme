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

	lists, err := config.Certificates()
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
	_, err = config.Certificates()
	if err == nil {
		t.Error("failed to detect chain of length 2")
	}
	config.Sites[2].UseKeyOf = ""

	config.Sites[0].UseKeyOf = "misspelled.examples.com"
	_, err = config.Certificates()
	if err == nil {
		t.Error("failed to detect mis-spelled domain name")
	}
}
