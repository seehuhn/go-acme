// seehuhn.de/go/acme/servercert - a command line tool to manage TLS certificates
// Copyright (C) 2020  Jochen Voss <voss@seehuhn.de>
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

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"seehuhn.de/go/acme/cert"
)

type table struct {
	header []string
	rows   [][]string
}

func (T *table) SetHeader(names ...string) {
	T.header = names
}

func (T *table) AddRow(row ...string) {
	T.rows = append(T.rows, row)
}

func readConfig(fname string) (*cert.Config, error) {
	fd, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	config := &cert.Config{}
	dec := yaml.NewDecoder(fd)
	err = dec.Decode(config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (T *table) Show() {
	ww := make([]int, len(T.header))
	for i, name := range T.header {
		ww[i] = utf8.RuneCountInString(name)
	}
	for _, row := range T.rows {
		for i, text := range row {
			w := utf8.RuneCountInString(text)
			if w > ww[i] {
				ww[i] = w
			}
		}
	}

	parts := make([]string, len(ww))
	for i, text := range T.header {
		parts[i] = fmt.Sprintf("%-*s", ww[i], text)
	}
	fmt.Println(strings.Join(parts, " | "))
	for i, w := range ww {
		parts[i] = strings.Repeat("-", w)
	}
	fmt.Println(strings.Join(parts, "-+-"))
	for _, row := range T.rows {
		for i, text := range row {
			parts[i] = fmt.Sprintf("%-*s", ww[i], text)
		}
		fmt.Println(strings.Join(parts, " | "))
	}
}

// List prints a table with information about all known certificates to stdout.
func List(m *cert.Manager) error {
	infos, err := m.GetCertInfo()
	if err != nil {
		return err
	}

	T := &table{}
	T.SetHeader("domain", "valid", "expiry time", "comment")
	for _, info := range infos {
		var tStr string
		if !info.Expiry.IsZero() {
			dt := time.Until(info.Expiry)
			if dt <= 0 {
				tStr = "expired"
			} else if dt > 48*time.Hour {
				tStr = fmt.Sprintf("%.1f days", float64(dt)/float64(24*time.Hour))
			} else {
				tStr = dt.Round(time.Second).String()
			}
		}
		T.AddRow(info.Domain, fmt.Sprint(info.IsValid), tStr, info.Message)
	}
	T.Show()
	return nil
}

// Renew all certificates which are not valid for at least 7 more days.
func Renew(m *cert.Manager) error {
	infos, err := m.GetCertInfo()
	if err != nil {
		return err
	}

	deadline := time.Now().Add(7 * 24 * time.Hour)
	for i, info := range infos {
		if info.IsValid && info.Expiry.After(deadline) {
			dt := time.Until(info.Expiry)
			var tStr string
			if dt > 48*time.Hour {
				tStr = fmt.Sprintf("%.1f days", float64(dt)/float64(24*time.Hour))
			} else {
				tStr = dt.Round(time.Second).String()
			}
			fmt.Println(info.Domain, "is valid for another "+tStr)
			continue
		}
		fmt.Println("renewing", info.Domain)
		err = m.RenewCertificate(i)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.Parse()

	config, err := readConfig("config.yml")
	if err != nil {
		log.Fatal(err)
	}

	m, err := cert.NewManager(config, true)
	if err != nil {
		log.Fatal(err)
	}

	// m.InstallDummyCert(1, 10*time.Second)

	cmd := flag.Arg(0)

	switch cmd {
	case "ignore":
		// pass
	case "list":
		err = List(m)
	case "renew":
		err = Renew(m)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}
