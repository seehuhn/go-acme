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
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"seehuhn.de/go/acme/cert"
)

var cmds = map[string]func(*cert.Config, *cert.Manager, ...string) error{
	"check":       CmdCheck,
	"list":        CmdList,
	"renew":       CmdRenew,
	"self-signed": CmdSelfSigned,
}

var configFileName = flag.String("c", "config.yml",
	"name of the configuration file")

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

type dirStatus int

func isFile(fname string) (os.FileMode, error) {
	stat, err := os.Stat(fname)
	if os.IsNotExist(err) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return stat.Mode(), nil
}

// CmdCheck checks the data from the configuration file for correctness and
// consistency.
func CmdCheck(c *cert.Config, m *cert.Manager, args ...string) error {
	var errors []string
	var warnings []string

	dirSeen := make(map[string]bool)
	dirChecked := make(map[string]bool)
	checkDir := func(dirType, dirName string, checkPerms bool) (string, error) {
		if dirName == "" {
			msg := dirType + " not set"
			errors = append(errors, msg)
			return msg, nil
		}

		stat, err := os.Stat(dirName)
		if os.IsNotExist(err) {
			msg := fmt.Sprintf("%s %q does not exist", dirType, dirName)
			if !dirSeen[dirName] {
				dirSeen[dirName] = true
				errors = append(errors, msg)
			}
			return msg, nil
		} else if err != nil {
			return "", err
		}
		if !stat.IsDir() {
			msg := fmt.Sprintf("%s %q is not a directory", dirType, dirName)
			if !dirSeen[dirName] {
				dirSeen[dirName] = true
				errors = append(errors, msg)
			}
			return msg, nil
		}

		if stat.Mode()&0022 != 0 {
			msg := fmt.Sprintf("%s %q has insecure permissions",
				dirType, dirName)
			if !dirChecked[dirName] {
				dirChecked[dirName] = true
				warnings = append(warnings, msg)
			}
			return msg, nil
		}

		return "", nil
	}

	_, err := checkDir("accountdir", c.AccountDir, true)
	if err != nil {
		return err
	}

	T := &table{}
	T.SetHeader("domain", "chall.", "key", "comments")
	seen := make(map[string]bool)
	if len(c.Sites) == 0 {
		warnings = append(warnings, "no sites specified")
	}
	for _, site := range c.Sites {
		domain := site.Domain
		if seen[domain] {
			errors = append(errors, "duplicate domain "+domain)
			continue
		}
		seen[domain] = true

		challenge := "n/a"
		key := "n/a"
		msg := ""

		if site.UseKeyOf != "" {
			if site.KeyFile != "" || site.CertFile != "" {
				msg = "uses both usekeyof and keyfile/certfile"
				errors = append(errors, domain+" "+msg)
			} else {
				msg = "shares key/cert with " + site.UseKeyOf
			}
			T.AddRow(domain, challenge, key, msg)
			continue
		}

		keyFile, err := c.GetKeyFileName(domain)
		if err != nil {
			return err
		}
		keyDir := filepath.Dir(keyFile)
		m2, err := checkDir("key directory", keyDir, true)
		if err != nil {
			return err
		}
		if m2 == "" {
			mode, err := isFile(keyFile)
			if err != nil {
				return err
			}
			if mode == 0 {
				key = "missing"
			} else if !mode.IsRegular() {
				key = "error"
				msg = fmt.Sprintf("%q is not a regular file", keyFile)
				errors = append(errors, msg)
			} else if mode&0007 != 0 {
				key = "errors"
				msg = fmt.Sprintf("%q has insecure permissions", keyFile)
				errors = append(errors, msg)
			} else {
				key = "ok"
			}
		} else {
			key = "error"
			if msg == "" {
				msg = m2
			}
		}

		err = m.TestChallenge(domain)
		if err != nil {
			challenge = "error"
			m2 := "cannot answer challenges"
			if msg == "" {
				msg = m2
			}
			errors = append(errors, m2+" for "+domain+":\n  "+err.Error())
		} else {
			challenge = "ok"
		}
		T.AddRow(domain, challenge, key, msg)
	}
	T.Show()

	if len(warnings) > 0 {
		fmt.Print("\nWarnings:\n")
		for _, w := range warnings {
			fmt.Println("- " + w)
		}
	}

	if len(errors) > 0 {
		fmt.Print("\nErrors:\n")
		for _, e := range errors {
			fmt.Println("- " + e)
		}
		err = fmt.Errorf("%d errors / %d warnings", len(errors), len(warnings))
	} else {
		err = nil
	}
	fmt.Println()

	return err
}

// CmdList prints a table with information about all known certificates to stdout.
func CmdList(c *cert.Config, m *cert.Manager, args ...string) error {
	ff := flag.NewFlagSet("list", flag.ExitOnError)
	ff.Parse(args)

	domains := ff.Args()
	if len(domains) == 0 {
		domains = c.Domains()
	}

	T := &table{}
	T.SetHeader("domain", "valid", "expiry time", "comment")
	for _, site := range c.Sites {
		domain := site.Domain

		if site.UseKeyOf != "" {
			T.AddRow(domain, "n/a", "n/a",
				"shares key/cert with "+site.UseKeyOf)
			continue
		}

		info, err := m.GetCertInfo([]string{domain})
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

// CmdRenew renews all certificates which are not valid for at least 7 more
// days.
func CmdRenew(c *cert.Config, m *cert.Manager, args ...string) error {
	ff := flag.NewFlagSet("renew", flag.ExitOnError)
	force := ff.Bool("f", false, "renew even if the old cert is still good")
	ff.Parse(args)

	domains := ff.Args()
	doRenew := make(map[string]bool)
	for _, site := range domains {
		doRenew[site] = false
	}
	for _, domain := range c.Domains() {
		if _, ok := doRenew[domain]; ok || len(domains) == 0 {
			doRenew[domain] = true
		}
	}
	for domain, isGood := range doRenew {
		if !isGood {
			return &cert.DomainError{
				Domain:  domain,
				Problem: "not in configuration file",
			}
		}
	}

	deadline := time.Now().Add(7 * 24 * time.Hour)
	for domain := range doRenew {
		info, err := m.GetCertInfo([]string{domain})
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
		err = m.RenewCertificate([]string{domain})
		if err != nil {
			return err
		}
	}
	return nil
}

// CmdSelfSigned installs a self-signed dummy certificate for a domain.
func CmdSelfSigned(c *cert.Config, m *cert.Manager, args ...string) error {
	ff := flag.NewFlagSet("self-signed", flag.ExitOnError)
	force := ff.Bool("f", false, "replace valid certificates")
	ff.Parse(args)

	domains := ff.Args()
	if len(domains) == 0 {
		return errors.New("no domains given")
	}
	for _, domain := range domains {
		if !*force {
			info, err := m.GetCertInfo([]string{domain})
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

func main() {
	debug := flag.Bool("D", true,
		"debug mode (relaxed rate limits, but invalid certifiates)")
	version := flag.Bool("version", false,
		"output version information and exit")

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
	if *version {
		fmt.Println(cert.PackageVersion)
		os.Exit(0)
	}
	if len(args) == 0 {
		flag.Usage()
		os.Exit(0)
	}

	if *debug {
		fmt.Fprint(os.Stderr, "\nRUNNING IN DEBUG MODE\n\n")
	}

	config, err := readConfig(*configFileName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	m, err := cert.NewManager(config, *debug)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	fn, ok := cmds[args[0]]
	if ok {
		err = fn(config, m, args[1:]...)
	} else {
		err = fmt.Errorf("unknown command %q", args[0])
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
