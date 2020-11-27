// seehuhn.de/go/acme/servercert - renew and manage server certificates
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

package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"seehuhn.de/go/acme/cert"
)

var cmds = map[string]func(*cert.Config, *cert.Manager, ...string) error{
	"check-cert":       CmdCheckCert,
	"check-config":     CmdCheckConfig,
	"renew":            CmdRenew,
	"self-signed":      CmdSelfSigned,
	"show-server-cert": CmdShowServerCert,
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

// CmdCheckCert prints a table with information about all known certificates to
// stdout.
func CmdCheckCert(c *cert.Config, m *cert.Manager, args ...string) error {
	certs, err := c.CertDomains()
	if err != nil {
		return err
	}

	T := &table{}
	T.SetHeader("domain", "valid", "expiry time", "server", "comment")

	for _, domains := range certs {
		mainDomain := domains[0]

		info, err := m.GetCertInfo(mainDomain)
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

		var sStr string
		port, err := c.GetTLSPort(mainDomain)
		if err != nil {
			return err
		}
		serverCert, err := getServerCertDER(mainDomain, strconv.Itoa(port))
		if err != nil {
			sStr = "error"
		} else if !bytes.Equal(serverCert, info.Cert.Raw) {
			sStr = "outdated"
		} else {
			sStr = "ok"
		}

		msg := info.Message
		if msg == "" {
			msg = "issued by " + info.Cert.Issuer.String()
		}
		T.AddRow(mainDomain, fmt.Sprint(info.IsValid), tStr, sStr, msg)

		for _, domain := range domains[1:] {
			valid := info.IsValid
			msg := ""

			if valid {
				err = info.Cert.VerifyHostname(domain)
				if err != nil {
					valid = false
					msg = "domain name not on certificate"
				}
			}

			port, err := c.GetTLSPort(domain)
			if err != nil {
				return err
			}
			serverCert, err = getServerCertDER(domain, strconv.Itoa(port))
			if err != nil {
				sStr = "error"
			} else if !bytes.Equal(serverCert, info.Cert.Raw) {
				sStr = "outdated"
			} else {
				sStr = "ok"
			}

			T.AddRow("  "+domain, fmt.Sprint(valid), " \"", sStr, msg)
		}
	}
	T.Show()

	return nil
}

// CmdCheckConfig checks the data from the configuration file for correctness and
// consistency.
func CmdCheckConfig(c *cert.Config, m *cert.Manager, args ...string) error {
	var errors []string
	var warnings []string

	dirSeen := make(map[string]bool)
	checkDir := func(dirType, dirName string) (string, error) {
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

		return "", nil
	}

	_, err := checkDir("accountdir", c.AccountDir)
	if err != nil {
		return err
	}

	T := &table{}
	T.SetHeader("domain", "key", "cert", "chall.", "comments")
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

		key := "-"
		cert := "-"
		var challenge string
		msg := ""

		err = c.TestChallenge(domain)
		if err != nil {
			challenge = "error"
			msg = "cannot respond to challenges"
			root, e2 := c.GetWebRoot(domain)
			if e2 != nil {
				return e2
			}
			errors = append(errors,
				msg+" for "+domain+":\n"+
					"  trying to publish at "+root+"\n"+
					"  "+err.Error())
		} else {
			challenge = "ok"
		}

		if site.UseKeyOf != "" {
			var m2 string
			if site.KeyFile != "" || site.CertFile != "" {
				m2 = "uses both usekeyof and keyfile/certfile"
				errors = append(errors, domain+" "+m2)
			} else {
				m2 = "shares key/cert with " + site.UseKeyOf
			}
			if msg == "" {
				msg = m2
			}
			T.AddRow(domain, key, cert, challenge, msg)
			continue
		}

		keyFile, err := c.GetKeyFileName(domain)
		if err != nil {
			return err
		}
		keyDir := filepath.Dir(keyFile)
		m2, err := checkDir("key directory", keyDir)
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
			} else {
				key = "present"
			}
		} else {
			key = "error"
			if msg == "" {
				msg = m2
			}
		}

		certFile, err := c.GetCertFileName(domain)
		if err != nil {
			return err
		}
		certDir := filepath.Dir(certFile)
		m2, err = checkDir("cert directory", certDir)
		if err != nil {
			return err
		}
		if m2 == "" {
			mode, err := isFile(certFile)
			if err != nil {
				return err
			}
			if mode == 0 {
				cert = "missing"
			} else if !mode.IsRegular() {
				cert = "error"
				msg = fmt.Sprintf("%q is not a regular file", certFile)
				errors = append(errors, msg)
			} else {
				cert = "present"
			}
		} else {
			cert = "error"
			if msg == "" {
				msg = m2
			}
		}
		T.AddRow(domain, key, cert, challenge, msg)
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

// CmdRenew renews all certificates which are not valid for at least 7 more
// days.
func CmdRenew(c *cert.Config, m *cert.Manager, args ...string) error {
	ff := flag.NewFlagSet("renew", flag.ExitOnError)
	force := ff.Bool("f", false, "renew even if the old cert is still good")
	ff.Parse(args)

	requested := ff.Args()
	known, err := c.CertDomains()
	if err != nil {
		return err
	}

	// doRenew has three possible states for each domain:
	//   not in map - not requested
	//   false - requested, but not in configuration file
	//   true - requested and in configuration file
	doRenew := make(map[string]bool)
	for _, site := range requested {
		doRenew[site] = false // we update this later where needed
	}
	for _, domains := range known {
		domain := domains[0]
		if _, ok := doRenew[domain]; ok || len(requested) == 0 {
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
	for _, domains := range known {
		domain := domains[0]
		if !doRenew[domain] {
			continue
		}

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
		err = m.RenewCertificate(domains)
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

// CmdShowServerCert downloads a certificate from a server and displays
// the data contained.
func CmdShowServerCert(c *cert.Config, m *cert.Manager, args ...string) error {
	ff := flag.NewFlagSet("show-server-cert", flag.ExitOnError)
	ff.Parse(args)

	domains := ff.Args()
	for _, domain := range domains {
		port := 443
		if strings.Contains(domain, ":") {
			parts := strings.SplitN(domain, ":", 2)
			domain = parts[0]
			p64, err := strconv.ParseUint(parts[1], 10, 16)
			if err != nil {
				return err
			}
			port = int(p64)
		}

		chain, err := getServerCertChain(domain, strconv.Itoa(port))
		if err != nil {
			return err
		} else if len(chain) == 0 {
			fmt.Print("cannot download server certificate for " + domain + "\n\n")
			continue
		}

		info, err := m.CheckCert(time.Now(), chain, domain)
		if err != nil {
			return err
		}
		if !info.IsValid {
			fmt.Println("\nINVALID CERTIFICATE:\n" + info.Message)
			continue
		}

		for i, chain := range info.Chains {
			if i > 0 {
				fmt.Println()
				fmt.Println()
				fmt.Println("*** alternative certificate chain:")
			}
			for j, cert := range chain {
				fmt.Println()
				printCert(cert, fmt.Sprintf("%-4d", j+1), "    ")
			}
		}
	}
	return nil
}

func main() {
	debug := flag.Bool("D", true,
		"debug mode (relaxed rate limits, but invalid certificates)")
	version := flag.Bool("version", false,
		"output version information and exit")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"usage: %s [options] command [arguments]\n\n", cmdName)
		fmt.Fprintln(flag.CommandLine.Output(), "Valid options are:")
		flag.PrintDefaults()
		fmt.Fprintln(flag.CommandLine.Output(), "\nCommand must be one of")
		var keys []string
		for key := range cmds {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Println("    " + key)
		}
		fmt.Fprintf(flag.CommandLine.Output(),
			"\nUse \"%s command -h\" to get help about a specific command.\n",
			cmdName)
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

	directory := defaultACMEDirectory
	roots, err := x509.SystemCertPool()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	if *debug {
		directory = debugACMEDirectory
		roots.AppendCertsFromPEM([]byte(fakeRootCert))
	}
	m, err := cert.NewManager(config, directory, roots)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	fn, ok := cmds[args[0]]
	if ok {
		err = fn(config, m, args[1:]...)
	} else {
		err = fmt.Errorf(
			"unknown command %q, use \"%s -help\" for help",
			args[0], cmdName)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

var cmdName string

func init() {
	cmdName = filepath.Base(os.Args[0])
}
