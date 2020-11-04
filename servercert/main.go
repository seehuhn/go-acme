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
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"seehuhn.de/go/acme/cert"
)

var cmds = map[string]func(*cert.Manager, ...string) error{
	"check":       CmdCheck,
	"list":        CmdList,
	"renew":       CmdRenew,
	"self-signed": CmdSelfSigned,
	"version":     CmdVersion,
}

var configFileName = flag.String("c", "config.yml",
	"name of the configuration file")

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

// CmdCheck checks the data from the configuration file for correctness and
// consistency.
func CmdCheck(m *cert.Manager, args ...string) error {
	err := m.CheckConfig()
	if fe, ok := err.(*cert.FileError); ok {
		fe.FileName = *configFileName
	}
	return err
}

// CmdList prints a table with information about all known certificates to stdout.
func CmdList(m *cert.Manager, args ...string) error {
	ff := flag.NewFlagSet("list", flag.ExitOnError)
	ff.Parse(args)

	domains := ff.Args()
	if len(domains) == 0 {
		domains = m.Domains()
	}

	T := &table{}
	T.SetHeader("domain", "valid", "expiry time", "comment")
	for _, domain := range domains {
		info, err := m.GetCertInfo(domain)
		if err != nil {
			return err
		}

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

// CmdRenew all certificates which are not valid for at least 7 more days.
func CmdRenew(m *cert.Manager, args ...string) error {
	ff := flag.NewFlagSet("renew", flag.ExitOnError)
	force := ff.Bool("f", false, "renew even if the old cert is still good")
	ff.Parse(args)

	domains := ff.Args()
	doRenew := make(map[string]bool)
	for _, site := range domains {
		doRenew[site] = false
	}
	for _, domain := range m.Domains() {
		if _, ok := doRenew[domain]; ok || len(domains) == 0 {
			doRenew[domain] = true
		}
	}
	for domain, isGood := range doRenew {
		if !isGood {
			return &cert.DomainError{Domain: domain}
		}
	}

	deadline := time.Now().Add(7 * 24 * time.Hour)
	for domain := range doRenew {
		info, err := m.GetCertInfo(domain)
		if err != nil {
			return err
		}

		if !*force && info.IsValid && info.Expiry.After(deadline) {
			dt := time.Until(info.Expiry)
			var tStr string
			if dt > 48*time.Hour {
				tStr = fmt.Sprintf("%.1f days", float64(dt)/float64(24*time.Hour))
			} else {
				tStr = dt.Round(time.Second).String()
			}
			fmt.Println(domain, "is valid for another "+tStr)
			continue
		}
		fmt.Println("renewing", domain)
		err = m.RenewCertificate(domain)
		if err != nil {
			return err
		}
	}
	return nil
}

// CmdSelfSigned installs a self-signed dummy certificate for a domain.
func CmdSelfSigned(m *cert.Manager, args ...string) error {
	ff := flag.NewFlagSet("self-signed", flag.ExitOnError)
	force := ff.Bool("f", false, "replace valid certificates")
	ff.Parse(args)

	domains := ff.Args()
	if len(domains) == 0 {
		return errors.New("no domains given")
	}
	for _, domain := range domains {
		if !*force {
			info, err := m.GetCertInfo(domain)
			if err != nil {
				return err
			}
			if info.IsValid {
				return errors.New(domain + " has a valid certificate")
			}
		}

		fmt.Println("installing self-signed certificate for " + domain + " ...")
		err := m.InstallSelfSigned(domain, time.Hour)
		if err != nil {
			return err
		}
	}
	return nil
}

func CmdVersion(m *cert.Manager, args ...string) error {
	fmt.Println(cert.PackageVersion)
	return nil
}

func main() {
	debug := flag.Bool("D", true,
		"debug mode (relaxed rate limits, but invalid certifiates)")

	flag.Usage = func() {
		name := filepath.Base(os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(),
			"usage: %s [options] command [arguments]\n\n", name)
		fmt.Fprintln(flag.CommandLine.Output(), "Valid options are:")
		flag.PrintDefaults()
		fmt.Fprintln(flag.CommandLine.Output(), "\nCommand must be one of")
		for key := range cmds {
			fmt.Println("    " + key)
		}
		fmt.Fprintf(flag.CommandLine.Output(),
			"\nUse \"%s command -h\" to get help about a specific command.\n",
			name)
	}
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(0)
	}

	if *debug {
		fmt.Fprint(os.Stderr, "\nRUNNING IN DEBUG MODE\n\n")
	}

	config, err := readConfig(*configFileName)
	if err != nil {
		log.Fatal(err)
	}

	m, err := cert.NewManager(config, *debug)
	if err != nil {
		log.Fatal(err)
	}

	fn, ok := cmds[args[0]]
	if ok {
		err = fn(m, args[1:]...)
	} else {
		err = fmt.Errorf("unknown command %q", args[0])
	}

	if err != nil {
		log.Fatal(err)
	}
}
