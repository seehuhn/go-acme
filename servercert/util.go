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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func isFile(fname string) (os.FileMode, error) {
	stat, err := os.Stat(fname)
	if os.IsNotExist(err) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return stat.Mode(), nil
}

func getServerCertDER(domain, port string) ([]byte, error) {
	certs, err := getServerCertChain(domain, port)
	if err != nil {
		return nil, err
	} else if len(certs) == 0 {
		return nil, errNoCert
	}
	return certs[0].Raw, nil
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

func printCert(cert *x509.Certificate) {
	if len(cert.DNSNames) > 0 {
		fmt.Println("DNSNames:")
		for _, name := range cert.DNSNames {
			fmt.Println("    " + name)
		}
	}
	if len(cert.EmailAddresses) > 0 {
		fmt.Println("EmailAddresses:")
		for _, email := range cert.EmailAddresses {
			fmt.Println("    " + email)
		}
	}
	if len(cert.IPAddresses) > 0 {
		fmt.Print("IPAddresses:")
		for _, addr := range cert.IPAddresses {
			fmt.Print("    " + addr.String())
		}
		fmt.Println()
	}
	if len(cert.IPAddresses) > 0 {
		fmt.Print("URIs:")
		for _, uri := range cert.URIs {
			fmt.Print("    " + uri.String())
		}
		fmt.Println()
	}
	fmt.Println("Subject:", cert.Subject)
	fmt.Println("Issuer:", cert.Issuer)
	fmt.Println("NotBefore:",
		cert.NotBefore.Local().Format("2006-01-02 15:04:05"))
	fmt.Println("NotAfter:",
		cert.NotAfter.Local().Format("2006-01-02 15:04:05"))

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
	fmt.Println("KeyUsage:")
	usage := cert.KeyUsage
	for _, entry := range tab {
		if usage&entry.Val != 0 {
			fmt.Println("    " + entry.Desc)
			usage &= ^entry.Val
		}
	}
	if usage != 0 {
		fmt.Printf("    %x (unknown bits)\n", usage)
	}

	if len(cert.ExtKeyUsage) > 0 {
		fmt.Println("ExtKeyUsage:")
		for _, usage := range cert.ExtKeyUsage {
			switch usage {
			case x509.ExtKeyUsageAny:
				fmt.Println("    Any")
			case x509.ExtKeyUsageServerAuth:
				fmt.Println("    ServerAuth")
			case x509.ExtKeyUsageClientAuth:
				fmt.Println("    ClientAuth")
			case x509.ExtKeyUsageCodeSigning:
				fmt.Println("    CodeSigning")
			case x509.ExtKeyUsageEmailProtection:
				fmt.Println("    EmailProtection")
			case x509.ExtKeyUsageIPSECEndSystem:
				fmt.Println("    IPSECEndSystem")
			case x509.ExtKeyUsageIPSECTunnel:
				fmt.Println("    IPSECTunnel")
			case x509.ExtKeyUsageIPSECUser:
				fmt.Println("    IPSECUser")
			case x509.ExtKeyUsageTimeStamping:
				fmt.Println("    TimeStamping")
			case x509.ExtKeyUsageOCSPSigning:
				fmt.Println("    OCSPSigning")
			case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
				fmt.Println("    MicrosoftServerGatedCrypto")
			case x509.ExtKeyUsageNetscapeServerGatedCrypto:
				fmt.Println("    NetscapeServerGatedCrypto")
			case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
				fmt.Println("    MicrosoftCommercialCodeSigning")
			case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
				fmt.Println("    MicrosoftKernelCodeSigning")
			default:
				fmt.Printf("    unknown %d\n", usage)
			}
		}
	}

	fmt.Println("PublicKeyAlgorithm:", cert.PublicKeyAlgorithm)
	fmt.Println("SignatureAlgorithm:", cert.SignatureAlgorithm)
}
