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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	flag.Parse()

	err := CmdShowServerCert(flag.Args()...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
}

// CmdShowServerCert downloads a certificate from a server and displays
// the data contained.
func CmdShowServerCert(domains ...string) error {
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

		info, err := checkCert(time.Now(), chain, domain)
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

func getServerCertChain(domain, port string) ([]*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", domain+":"+port, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates, nil
}

func printCert(cert *x509.Certificate, head, pad string) {
	pp := func(parts ...string) {
		parts = append([]string{head + parts[0]}, parts[1:]...)
		fmt.Println(strings.Join(parts, " "))
		head = pad
	}

	if len(cert.DNSNames) > 0 {
		pp("DNSNames:")
		for _, name := range cert.DNSNames {
			pp("    " + name)
		}
	}
	if len(cert.EmailAddresses) > 0 {
		pp("EmailAddresses:")
		for _, email := range cert.EmailAddresses {
			pp("    " + email)
		}
	}
	if len(cert.IPAddresses) > 0 {
		pp("IPAddresses:")
		for _, addr := range cert.IPAddresses {
			pp("    " + addr.String())
		}
	}
	if len(cert.IPAddresses) > 0 {
		pp("URIs:")
		for _, uri := range cert.URIs {
			pp("    " + uri.String())
		}
	}
	pp("Subject:", cert.Subject.String())
	pp("Issuer:", cert.Issuer.String())
	pp("Valid:", cert.NotBefore.Local().Format("2006-01-02 15:04:05"),
		"to", cert.NotAfter.Local().Format("2006-01-02 15:04:05"))

	tab := []*struct {
		Val  x509.KeyUsage
		Desc string
	}{
		{x509.KeyUsageDigitalSignature, "DigitalSignature"},
		{x509.KeyUsageContentCommitment, "ContentCommitment"},
		{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
		{x509.KeyUsageDataEncipherment, "DataEncipherment"},
		{x509.KeyUsageKeyAgreement, "KeyAgreement"},
		{x509.KeyUsageCertSign, "CertSign"},
		{x509.KeyUsageCRLSign, "CRLSign"},
		{x509.KeyUsageEncipherOnly, "EncipherOnly"},
		{x509.KeyUsageDecipherOnly, "DecipherOnly"},
	}
	pp("KeyUsage:")
	usage := cert.KeyUsage
	for _, entry := range tab {
		if usage&entry.Val != 0 {
			pp("    " + entry.Desc)
			usage &= ^entry.Val
		}
	}
	if usage != 0 {
		pp(fmt.Sprintf("    %x (unknown bits)\n", usage))
	}

	if len(cert.ExtKeyUsage) > 0 {
		pp("ExtKeyUsage:")
		for _, usage := range cert.ExtKeyUsage {
			switch usage {
			case x509.ExtKeyUsageAny:
				pp("    Any")
			case x509.ExtKeyUsageServerAuth:
				pp("    ServerAuth")
			case x509.ExtKeyUsageClientAuth:
				pp("    ClientAuth")
			case x509.ExtKeyUsageCodeSigning:
				pp("    CodeSigning")
			case x509.ExtKeyUsageEmailProtection:
				pp("    EmailProtection")
			case x509.ExtKeyUsageIPSECEndSystem:
				pp("    IPSECEndSystem")
			case x509.ExtKeyUsageIPSECTunnel:
				pp("    IPSECTunnel")
			case x509.ExtKeyUsageIPSECUser:
				pp("    IPSECUser")
			case x509.ExtKeyUsageTimeStamping:
				pp("    TimeStamping")
			case x509.ExtKeyUsageOCSPSigning:
				pp("    OCSPSigning")
			case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
				pp("    MicrosoftServerGatedCrypto")
			case x509.ExtKeyUsageNetscapeServerGatedCrypto:
				pp("    NetscapeServerGatedCrypto")
			case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
				pp("    MicrosoftCommercialCodeSigning")
			case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
				pp("    MicrosoftKernelCodeSigning")
			default:
				pp(fmt.Sprintf("    unknown %d\n", usage))
			}
		}
	}
}

// Info contains information about a single certificate installed on the
// system.
type Info struct {
	Cert      *x509.Certificate
	Chains    [][]*x509.Certificate
	IsValid   bool
	IsMissing bool
	Expiry    time.Time
	Message   string
}

func checkCert(now time.Time, chain []*x509.Certificate, domain string) (*Info, error) {
	info := &Info{}

	if len(chain) == 0 {
		info.IsMissing = true
		info.Message = "missing"
		return info, nil
	}

	siteCert := chain[0]
	info.Cert = siteCert
	info.Expiry = siteCert.NotAfter

	intermediates := x509.NewCertPool()
	for _, caCert := range chain[1:] {
		intermediates.AddCert(caCert)
	}
	opts := x509.VerifyOptions{
		DNSName:       domain,
		Intermediates: intermediates,
		CurrentTime:   now,
	}
	chains, err := siteCert.Verify(opts)
	if err != nil {
		info.Message = err.Error()
		return info, nil
	}

	info.IsValid = true
	info.Chains = chains

	return info, nil
}
